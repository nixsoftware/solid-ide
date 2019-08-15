// extending nix to make use of solid

const JWE = nixSdk.jose.JWE;
const JWK = nixSdk.jose.JWK;
const Identity = nixSdk.Identity;
const VaultOps = nixSdk.constants.VaultOps;
const kidToCanonUserHostPath = nixSdk.util.kidToCanonUserHostPath;

const _fc = SolidFileClient;         // from solid-file-client.bundle.js

const ContentType = "Content-Type";
const TurtleMIMEType = "text/turtle";

// TODO - develop schema
const NixNS = $rdf.Namespace("https://www.nix.software/rdf-schema/nix_v1");

// TODOs
// - PodEncryptedStore:
//   - Add URIs to authenticated data to prevent attacks by moving / copying JWEs
//   - validate consistency of unsigned data against signed data
//   - swap formats to something LD-based where possible
//   - publish public identity + default identity information to public / webId profile

// Assuming we're starting with something like:
// https://robmccoll.solid.community/profile/card#me
// and that /public exists / is the right place
function webIDToPublicRoot(webID) {
  let url = new URL(webID);
  url.pathname = "/public/nix/";
  url.hash = '';
  url.search = '';
  return url.toString();
}

function webIDToPrivateRoot(webID) {
  let url = new URL(webID);
  url.pathname = "/private/nix/";
  url.hash = '';
  url.search = '';
  return url.toString();
}

class PodEncryptedStore {
  /* SHOULD NOT BE USED DIRECTLY - call fromPasswordKeyOrJWK() */
  constructor() {}

  static async fromPasswordKeyOrJWK({
    /* one of these three must be given */
    password = null,
    key      = null,
    jwk      = null,

    webID       = null,
    publicRoot  = null,
    privateRoot = null,
  } = {}) {
    let pes  = new PodEncryptedStore();

    pes.webID       = webID;
    pes.publicRoot  = publicRoot  || webIDToPublicRoot(webID);
    pes.privateRoot = privateRoot || webIDToPrivateRoot(webID);
    if(!pes.webID || !pes.publicRoot || !pes.privateRoot) {
      throw("webID is required. publicRoot and privateRoot can be derived, but must have values");
    }

    pes.inputKey = key;
    if(password) {
      pes.inputKey = await JWE.pbkdf2(password, "jweStore");
    }
    if(jwk) {
      pes.inputKey = await JWK.toAESGCMKey(pes.jwk);
    }

    // note that the "key" is only used to decrypt the intermediate key in the
    // datastore to allow changing this outer key without re-encrypting the
    // entire DB
    if(!pes.inputKey) {
      throw "key, password, or JWK is required";
    }
    if(pes.inputKey.algorithm.name !== "AES-GCM" || pes.inputKey.algorithm.length !== 256) {
      throw `unsupported key - only AES-GCM 256 - ${JSON.stringify(pes.inputKey.algorithm)}`;
    }

    return pes.startDB();
  }

  async startDB() {
    let intermediateKey = '';

    try {
      intermediateKey = await _fc.fetch(this.privateRoot + "store/intermediate.txt")

    } catch(err) {
      intermediateKey = (await JWE.encryptDirectAES256GCM(this.inputKey, JSON.stringify(await JWK.randomAESGCM()), "intermediateKey")).toCompact();

      await _fc.createFolder(this.privateRoot);
      await _fc.createFolder(this.privateRoot + "store/");
      await Promise.all(["store/identities/","store/config/"].map((folder) => _fc.createFolder(this.privateRoot + folder)));
      await Promise.all(["store/identities/byname","store/identities/bytype","store/identities/byaddress"].map((folder) => _fc.createFolder(this.privateRoot + folder)));
      await Promise.all(["store/identities/bytype/user","store/identities/bytype/app","store/identities/bytype/vault",
        "store/identities/bytype/route","store/identities/bytype/group"].map((folder) => _fc.createFolder(this.privateRoot + folder)));

      await _fc.createFile(this.privateRoot + "store/intermediate.txt", intermediateKey)

    } finally {
      try {
        this.key = await JWK.toAESGCMKey(JSON.parse(await JWE.fromCompact(intermediateKey).decryptDirectAES256GCM(this.inputKey)));
      } catch(e) {
        throw "given key / password / jwk could not be used to unlock the store: "  + e;
      }
    }
    return this;
  }

  async storeIdentity(identity) {
    let fullJSON = await identity.toJSONFull();
    await _fc.createFile(this.privateRoot + "store/identities/byaddress/" + identity.address + ".json", JSON.stringify({
      JWE: (await JWE.encryptDirectAES256GCM(this.key, fullJSON, identity.address)).toCompact(),
      address: identity.address,
      name:    identity.name,
      type:    identity.type,
    }))
    await _fc.updateFile(this.privateRoot + "store/identities/byname/" + btoa(identity.name) + ".txt", identity.address)
    await _fc.createFile(this.privateRoot + "store/identities/bytype/" + identity.type + "/" + identity.address + ".txt", identity.address)
  }

  async getIdentitiesByType(type) {
    let folder = null;
    try {
      folder = await _fc.readFolder(this.privateRoot + "store/identities/bytype/" + type + "/")
    } catch(err) {
      return [];
    }

    let downloads = folder.files.map((file) => _fc.fetch(this.privateRoot + "store/identities/byaddress/" + file.name.replace(/\.txt$/, '') + ".json"));
    let objs = await Promise.all(downloads);
    let out = [];
    for(let i = 0; i < objs.length; i++) {
      let fullJSON = await JWE.fromCompact(JSON.parse(objs[i]).JWE).decryptDirectAES256GCM(this.key);
      out.push(await Identity.fromJSONFull(fullJSON));
    }
    return out;
  }

  async getIdentityByName(name) {
    let address = '';
    try {
      address = await _fc.fetch(this.privateRoot + "store/identities/byname/" + btoa(name) + ".txt");
    } catch(err) {
      return null;
    }

    let obj = JSON.parse(await _fc.fetch(this.privateRoot + "store/identities/byaddress/" + address + ".json"));
    let fullJSON = await JWE.fromCompact(obj.JWE).decryptDirectAES256GCM(this.key);
    return Identity.fromJSONFull(fullJSON);
  }

  async getIdentityByAddress(address) {
    let obj = null;
    try {
      obj = JSON.parse(await _fc.fetch(this.privateRoot + "store/identities/byaddress/" + address + ".json"));
    } catch(err) {
      return null;
    }
    let fullJSON = await JWE.fromCompact(obj.JWE).decryptDirectAES256GCM(this.key);
    return Identity.fromJSONFull(fullJSON);
  }

  async storeConfig(key, val) {
    await _fc.updateFile(this.privateRoot + "store/config/" + btoa(key) + ".json", JSON.stringify({
      JWE: (await JWE.encryptDirectAES256GCM(this.key, JSON.stringify(val), key)).toCompact(),
    }))

    if(key.startsWith("defaultIdentities.")) {
      let identity = await this.getIdentityByAddress(val);
      await this.setDefaultIdentityProfile(identity);
    }
  }

  async loadConfig(key) {
    let obj = null;
    try {
      obj = JSON.parse(await _fc.fetch(this.privateRoot + "store/config/" + btoa(key) + ".json"));
    } catch(err) {
      return null;
    }
    let json = await JWE.fromCompact(obj.JWE).decryptDirectAES256GCM(this.key);
    return JSON.parse(json);
  }

  async setDefaultIdentityProfile(identity) {
    let body = await _fc.fetch(this.webID, TurtleMIMEType);
    let graph = $rdf.graph();
    $rdf.parse(body, graph, this.webID, TurtleMIMEType);
    let identities = graph.each(this.webID, NixNS('primaryIdentities'));
    let foundIdent = null;
    for(let i = 0; i < identities.length; i++) {
      let type = graph.any(identities[i], NixNS('identityType'));
      if(type.value !== identity.type) {
        continue;
      }
      foundIdent = identities[i];
      graph.remove(foundIdent);
      break;
    }
    if(!foundIdent) {
      foundIdent = new $rdf.BlankNode();
    }
    graph.add(foundIdent, NixNS("identityType"), identity.type, this.webID);
    graph.add(foundIdent, NixNS("address"), identity.address, this.webID);
    graph.add(foundIdent, NixNS("pubSigJWK"), JSON.stringify(await identity.getSigPubJWK()), this.webID);
    graph.add(foundIdent, NixNS("pubEncJWK"), JSON.stringify(await identity.getEncPubJWK()), this.webID);
    graph.add(this.webID, NixNS("primaryIdentities"), foundIdent, this.webID);
    body = await $rdf.serialize(undefined, graph, this.webID, TurtleMIMEType);
    return await _fc.fetch(this.webID, {
      method: 'PUT',
      headers: {
        [ContentType]: TurtleMIMEType,
      },
      body: body,
    });
  }
}

class PodEncryptedVault {
  constructor({
    webID       = null,
    publicRoot  = null,
    privateRoot = null,
  } = {}) {
    this.webID       = webID;
    this.publicRoot  = publicRoot  || webIDToPublicRoot(webID);
    this.privateRoot = privateRoot || webIDToPrivateRoot(webID);
    if(!this.webID || !this.publicRoot || !this.privateRoot) {
      throw("webID is required. publicRoot and privateRoot can be derived, but must have values");
    }
  }

  async forIdentity({
    identity = null,

    /* optional */
    dbName = null,
  } = {}) {
    let vault = new PodEncryptedVault({
      webID: this.webID,
      publicRoot: this.publicRoot,
      privateRoot: this.privateRoot,
    });

    vault.identity = identity;
    vault.vaultBase = vault.privateRoot + "vaults/" + identity.address + "/";
    // TODO set ourselves as the identity comm's key store

    let intermediateKey = '';

    try {
      intermediateKey = await _fc.fetch(vault.vaultBase + "intermediate.txt")

    } catch(err) {
      intermediateKey = (await JWE.encryptECDHESP256(
        vault.identity.comms.encPubKey, JSON.stringify(await JWK.randomAESGCM()), "intermediateKey"
      )).toCompact();

      await _fc.createFolder(vault.privateRoot);
      await _fc.createFolder(vault.privateRoot + "vaults/");
      await _fc.createFolder(vault.vaultBase);

      await Promise.all(["config/", "identities/", "globalperms/", "contentpkgperms/",
        "contentpkgs/", "msgids/"].map((folder) => _fc.createFolder(vault.vaultBase + folder)));
      await Promise.all(["config/", "identities/byaddress/", "globalperms/byperm/",
        "contentpkgperms/bykid/", "contentpkgs/bykid/", "msgids/"].map((folder) => _fc.createFolder(vault.vaultBase + folder)));

      await _fc.createFile(vault.vaultBase + "intermediate.txt", intermediateKey)

    } finally {
      try {
        vault.key = await JWK.toAESGCMKey(JSON.parse(await JWE.fromCompact(intermediateKey).
            decryptECDHEP256(vault.identity.comms.encPrivKey)));
      } catch(e) {
        throw "given key / password / jwk could not be used to unlock the store: "  + e;
      }
    }

    console.log("vault storage unlocked for ", identity);
    vault.latestTS = await vault.getConfig("latestTS");
    vault.writeLatestTS = null;

    return vault;
  }

  async _getURIOrDefault(uri, def) {
    let obj = null;
    try {
      obj = JSON.parse(await _fc.fetch(uri));
    } catch(err) {
      return def;
    }
    let jwe = await JWE.fromCompact(obj.JWE);
    let json = await jwe.decryptDirectAES256GCM(this.key);
    let kid = jwe.protectedObj.kid;
    if(kid !== uri) {
      throw("data may have been modified - signed URI didn't match " + kid + " " + uri);
    }
    return JSON.parse(json);
  }

  async _putURI(uri, value) {
    return await _fc.updateFile(uri, JSON.stringify({
      JWE: (await JWE.encryptDirectAES256GCM(this.key, JSON.stringify(value), uri)).toCompact(),
    }))
  }

  async _deleteURI(uri) {
    return await _fc.deleteFile(uri);
  }

  async setConfig(key, value) {
    return await this._putURI(this.vaultBase + "config/" + btoa(key) + ".json", value);
  }

  async getConfig(key) {
    return await this._getURIOrDefault(this.vaultBase + "config/" + btoa(key) + ".json", null);
  }

  async setAllowGlobal(addr, op) {
    const uri = this.vaultBase + "globalperms/byperm/" + op + ".json";
    let obj = await this._getURIOrDefault(uri, {});
    [addr] = kidToCanonUserHostPath(addr);
    obj[addr] = {allow: true};
    return await this._putURI(uri, obj);
  }

  async isAllowedGlobal(addr, op) {
    console.log("isAllowedGlobal", addr, op);
    let obj = await this._getURIOrDefault(this.vaultBase + "globalperms/byperm/" + op + ".json", {});
    [addr] = kidToCanonUserHostPath(addr);
    return obj[addr] ? obj[addr].allow : false;
  }

  async setAllowContentPackage(addr, op, kid) {
    const uri = this.vaultBase + "contentpkgperms/bykid/" + btoa(kid) + ".json";
    let obj = await this._getURIOrDefault(uri, {});
    [addr] = kidToCanonUserHostPath(addr);
    let canOp = obj[op] || {};
    canOp[addr] = {allow: true};
    obj[op] = canOp;
    return await this._putURI(uri, obj);
  }

  async isAllowedContentPackage(addr, op, kid, noGlobal) {
    console.log("isAllowedContentPackage", addr, op, kid, noGlobal);
    if ((!noGlobal) && (await this.isAllowedGlobal(addr, op))) {
      return true;
    }

    [addr] = kidToCanonUserHostPath(addr);
    let obj = await this._getURIOrDefault(this.vaultBase + "contentpkgperms/bykid/" + btoa(kid) + ".json", {});
    let canOp = obj[op] || {};
    return canOp[addr] ? canOp[addr].allow : false;
  }

  async gatherContentPackagePerms(kid) {
    let obj = await this._getURIOrDefault(this.vaultBase + "contentpkgperms/bykid/" + btoa(kid) + ".json", {});
    let perms = {};
    for(var op in Object.values(VaultOps)) {
      if(obj[op]) {
        perms[op] = Object.keys(obj[op]);
      }
    }
    return perms;
  }

  async processedBefore(ts, msgID) {
    let cut = ts.length - 9;
    let secs = ts.slice(0, cut);
    this.latestTS = (Number(secs) - (2 * 60) | 0) + ts.slice(cut);

    if(await this._getURIOrDefault(this.vaultBase + "msgids/" + btoa(msgID) + ".json", false)) {
      return true;
    }
    await this._putURI(this.vaultBase + "msgids/" + btoa(msgID) + ".json", true);

    if(!this.writeLatestTS) {
      this.writeLatestTS = setTimeout(() => {
        this.setConfig("latestTS", this.latestTS).then(() => {});
        this.writeLatestTS = null;
      }, 1000);
    }
    return false;
  }

  getLatestTS() {
    return this.latestTS
  }

  async setContentPackage(kid, pkg) {
    return await this._putURI(this.vaultBase + "contentpkgs/bykid/" + btoa(kid) + ".json", pkg);
  }

  async getContentPackage(kid) {
    return await this._getURIOrDefault(this.vaultBase + "contentpkgs/bykid/" + btoa(kid) + ".json", pkg, null);
  }

  async deleteContentPackage(kid, pkg) {
    return await this._deleteURI(this.vaultBase + "contentpkgs/bykid/" + btoa(kid) + ".json");
  }

  async whichIdentitiesCan(op, kid) {
    var addresses = {};

    let globalPerms = await this._getURIOrDefault(this.vaultBase + "globalperms/byperm/" + op + ".json", {});
    Object.keys(globalPerms).map((addr) => addresses[addr] = true);

    let contentPkgPerms = await this._getURIOrDefault(this.vaultBase + "contentpkgperms/bykid/" + btoa(kid) + ".json", {});
    let canOp = contentPkgPerms[op] || {};
    Object.keys(canOp).map((addr) => addresses[addr] = true);
    return Object.keys(addresses);
  }

  async deleteContentPackagePerms(kid, pkg) {
    return await this._deleteURI(this.vaultBase + "contentpkgperms/bykid/" + btoa(kid) + ".json");
  }
}
