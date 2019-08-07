if(!nixSdk) {
  console.error("nix-solid.js has an external dependency on nixSdk - not found!");
  throw("nix-solid.js has an external dependency on nixSdk - not found!");
}

// BIG TODO - actually define Nix ontology, swap in commonly used predicates
const NixNS = new $rdf.Namespace("https://www.nix.software/ld/v1#");
const NixNSIdentityName = NixNS("identityName");
const NixNSIdentityType = NixNS("identityType");
const MIMETurtle = 'text/turtle';

/*
class RecoveryAndPodEncryptedStore {
  constructur() {
    // should not be used - use static fromPod
  }

  static async fromPod({
    password = null,
    podRoot = null,
    optPath = "/nix/default",
    solidFileClient = null,
  } = {}) {
    let rps = new RecoveryAndPodEncryptedStore();

    if(!password) {
      throw("password is required");
    }

    if(!podRoot) {
      throw("podRoot is required");
    }

    if(!solidFileClient) {
      throw("solidFileClient is required");
    }

    rps.rootURI = (new URL(optPath || "/nix/default", podRoot)).toString();
    rps.identitiesURI = (new URL('identities.ttl', rps.rootURI)).toString();
    rps.configURI = (new URL('config.ttl', rps.rootURI)).toString();
    rps.solidFileClient = solidFileClient;

    rps.password = password;
    rps.key = await nixSdk.jose.JWE.pbkdf2(password, "jweStore");

    return rps.loadData();
  }

  async loadData() {
    try {
      this.identityGraph = await this.solidFileClient.fetchAndParse(this.identitiesURI);
    } catch(err) {
      this.identityGraph = $rdf.graph();
    }
    try {
      this.configGraph configTTL = await this.solidFileClient.fetchAndParse(this.configURI);
    } catch(err) {
      this.configGraph = $rdf.graph();
    }
  }

  setDefaults({
    defaultAPIKeyID     = null,
    defaultAPIKeySecret = null,
    defaultAPIKeyJWT    = null,
    defaultNixURL       = null,
  } = {}) {
    this.defaultAPIKeyID     = defaultAPIKeyID;
    this.defaultAPIKeySecret = defaultAPIKeySecret;
    this.defaultAPIKeyJWT    = defaultAPIKeyJWT;
    this.defaultNixURL       = defaultNixURL;
    this.defaultsSet         = true;
  }

  async storeIdentity(identity) {
    await identity.comms.setRecovery(await identity.comms.buildRecovery(this.password));
    let fullJSON = await identity.toFullJSON();
    let me = $rdf.sym(this.identitiesURI + "#" + identity.address);
    this.identityGraph.add(me, NixNSIdentityName, identity.name);
    this.identityGraph.add(me, NixNSIdentityType, identity.type);
    this.identityGraph.add(me, NixNSIdentityJWE, (
      await nixSdk.jose.JWE.encryptDirectAES256GCM(this.key, fullJSON, identity.address)).toCompact());
    return this.solidFileClient.updateFile(this.identitiesURI, this.identityGraph.serialize(), MIMETurtle);
  }

  async getIdentityByType(type) {
  }

  async getIdentityByName(name) {
  }

  async getIdentityByAddress(address) {
  }

  async storeConfig(key, val) {
    let me = $rdf.sym(this.configURI + "#" + key);
    this.configGraph.add(me, NixNSConfigJWE, (
      await nixSdk.jose.JWE.encryptDirectAES256GCM(this.key, JSON.stringify(val), key)).toCompact());
    return this.solidFileClient.updateFile(this.configURI, this.configGraph.serialize(), MIMETurtle);
  }

  async loadeConfig(key) {
    return null;
  }
}
*/

export {
};
