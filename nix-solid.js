// extending nix to make use of solid
const JWE = nixSdk.jose.JWE;
const JWK = nixSdk.jose.JWK;
const Identity = nixSdk.Identity;

const _fc = SolidFileClient;         // from solid-file-client.bundle.js

const ContentType = "Content-Type";
const TurtleMIMEType = "text/turtle";

// TODO - develop schema
const NixNS = $rdf.Namespace("https://www.nix.software/rdf-schema/nix_v1");

// TODOs
// - PodEncryptedStore:
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
