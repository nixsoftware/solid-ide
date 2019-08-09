/* VERSION 0.1.3
 **     2019-03-30
 */
const sol = new SolidHandler()      // from solid-ide-solidHandler.js
const fc = SolidFileClient;         // from solid-file-client.bundle.js
const auth = SolidAuthClient;         // from solid-file-client.bundle.js

let nixStore = null;
let nixClient = null;

var init = function(){
  app.getStoredPrefs()
  sol.get().then( results => {
    app.processResults(results)
  })
}

var fileDisplay = new Vue({
  el  : '#fileDisplay',
  data : {
    file:{content:''},
    displayState:localStorage.getItem('solDisplayState') || 'both'
  },
  methods : {
    initEditor : function(){
      this.zed = new SolidIdeEditor('editor');
      var keys  = app.editKeys  || "emacs"
      var theme = app.editTheme || "dark theme"
      this.setEditKeys(keys);
      this.setEditTheme(theme);
      this.zed.resize();
    },
    setEditKeys  : function(keys){
      var newKey ="zemacs";
      if(keys==='vim') newKey ="vim"
      this.zed.setKeys(newKey)
      this.keys = newKey;
    },
    setEditTheme  : function(theme){
      var newTheme = "github"
      if(theme.match("dark")){
        newTheme = "monokai"
      }
      this.zed.setTheme(newTheme)
      this.theme=newTheme
    },
    setContent : function(content){
      this.initEditor()
      this.file = app.currentThing;
      this.file.content = content;
      if(!this.file.type && this.file.url) 
        this.file.type = sol.guessFileType(this.file.url)
      this.zed.setModeFromType(this.file.type)
      this.zed.setContents(content)
      this.zed.ed.clearSelection() // remove blue overlay
    },
    saveEdits : function(){
      sol.replace(
        this.file.url,
        this.zed.getContents()
      ).then( success => {
        if(success){
          alert("Resource saved: " + this.file.url)
          app.get(this.file.url)
        }
        else alert("Couldn't save "+sol.err)
      })
    },
    encryptSelection : async function() {
      let ed = this.zed.ed;
      let selection = ed.getSelectedText();
      if(!selection) {
        return alert("No content selected. Please select content to encrypt");
      }

      let cipherText = await nixClient.encrypt(selection);
      ed.session.replace(ed.selection.getRange(), cipherText);
    },
    decryptSelection : async function() {
      let ed = this.zed.ed;
      let selection = ed.getSelectedText();
      if(!selection) {
        return alert("No content selected. Please select content to decrypt");
      }
      try {
        selection = await nixClient.decryptAll(selection);
      } catch(err) {
        console.log("decrypt failed", err);
        return alert("Data could not be decrypted. You may not have permission to access it.");
      }
      ed.session.replace(ed.selection.getRange(), selection);
    },
    togglePanes : function(event){
      this.displayState  = event.target.value;
      localStorage.setItem("solDisplayState", this.displayState);
      this.initEditor();
      return;
    },
  }
})

var app = new Vue({
  el: '#app',
  methods : {
    //
    // COMMUNICATE WITH THE SOLID SERVER
    //
    get : function(thing){ 
      if(typeof thing === "string") {
        thing = {url: thing}
      }
      var oldThing = this.currentThing
      this.currentThing = thing
      view.hide();
      sol.get(thing).then( results => {
        if(sol.err){
          alert(sol.err)
          if(oldThing.url===thing.url) 
            oldThing.url = sol.homeUrl;
          get(oldThing.url)
        }
        else this.processResults(results)
      })
    },
    rm : function(f){
      if(!this.perms.Control) return
      if( confirm("DELETE RESOURCE "+f.url+"???") ){
        view.hide('fileManager')
        view.hide('folderManager')
        var parentFolder =f.url.replace(f.name,'')
        sol.rm( f.url ).then( success =>{
          if(success){
            alert("Resource deleted: " + f.url)
            app.get(parentFolder)
          }
          else alert("Couldn't delete "+sol.err)
        })
      }
    },
    upload : async function(f){
      view.hide('folderManager')
      var inputFile = document.getElementById("upFile")
      for (var i = 0; i < inputFile.files.length; i++) {
        var content = inputFile.files[i] 
        var url  = this.folder.url+content.name;
        success = await sol.replace(url,content )
        if(success){
          alert("Resource created: " + content.name)
        }
        else alert("Couldn't create "+url+" "+sol.err)
      }
      app.get(this.folder.url)
    },        	
    addThing : function(type){
      if(!this.newThing.name){
        alert("You didn't supply a name!")
        return;
      }
      view.hide('folderManager')
      var name = this.newThing.name
      var url  = this.folder.url
      sol.add(url,name,type ).then( success => {
        if(success){
          alert("Resource created: " + name)
          app.get(this.folder.url)
        }
        else alert("Couldn't create "+url+" "+sol.err)
      })
    },
    manageResource : function(thing){
      if(!this.perms.Control) return
      if(thing.type==="folder"){
        this.folder = thing;
        view.show('folderManager');
      }
      else {
        this.file = thing;
        view.show('fileManager');
      }
    },
    getProfile : function(){ 
      var url =  this.webId.replace('#me','')
      app.get( url )
    },
    download : function(f){
      var a = document.createElement("a");
      a.href = f.url
      a.setAttribute("download", f.name);
      var b = document.createEvent("MouseEvents");
      b.initEvent("click", false, true);
      a.dispatchEvent(b);
      return false;
    },
    //
    // EDITOR & FILE MANAGER SETTINGS
    //
    setEditKeys  : function(){
      fileDisplay.setEditKeys(this.editKeys)
    },
    setEditTheme  : function(){
      fileDisplay.setEditTheme(this.editTheme)
    },
    //
    // LOGIN STATES
    //
    canControl : function(){
      if( this.perms.Control ) return "canControl"
    },
    setLogState : function(){
      if( this.loggedIn ){
        this.logState = "login"
        sol.webId=this.webId="";
        fc.logout().then( res => {
          app.get(sol.homeUrl)
        })
      }
      else { 
        this.logState = "logout"
        sol.homeUrl = this.homeUrl
        fc.logout().then( ()=> {
          auth.popupLogin({popupUri: 'popup.html'}).then(() => fc.checkSession()).then((sess) => {
            app.get(sess.webId)
          })
        })
      }
    },
    getLogState : function(status){
      var elm = document.getElementById('optionsButton')
      if(status.loggedIn){
        this.webId = status.webId
        this.logState = "logout";  // logState is the button label
        this.loggedIn = true;      // loggedIn is true/false

      }
      else{
        this.webId = ""
        this.logState = "login";
        this.loggedIn = false;
      }
      this.perms=status.permissions
    },
    nixLoad : async function(pass) {
      try {
        nixStore = await nixSdk.stores.LocalEncryptedStore.fromPasswordKeyOrJWK({password: pass});
      } catch(err) {
        this.nixPassErr = 'Decrypting storage failed. Does your passphrase match? Please try again.';
        return console.error('decrypting nix storage', err);
      }
      nixClient = await new nixSdk.Client({
        defaultAPIKeyID: 'agAIFBw@api.nix.software',
        defaultAPIKeySecret: '7vzuBreMxGV9ChiqZL7cRW3BVKpzI2skK0lJlh/8c0o=',
        store: nixStore,
      }).init();

      try {
        let short = (new URL(this.webId)).host;
        await nixClient.getOrCreateIdentityByName(`${short}#v`, nixSdk.constants.IdentityTypeVault);
        await nixClient.getOrCreateIdentityByName(`${short}#a`, nixSdk.constants.IdentityTypeApp);
      } catch(err) {
        this.nixPassErr = 'Loading or creating Nix identities failed.';
        return console.error("establishing nix identities", err);
      }

      this.nixLoaded = true;
    },
    //
    // LOCAL STORAGE OF PREFERENCES
    //
    storePrefs : function(){
      localStorage.setItem("solState", JSON.stringify({
        home : this.homeUrl,
        idp : sol.idp,
        keys : this.editKeys,
        theme : this.editTheme,
      }))
    },
    getStoredPrefs : function(){
      var state = localStorage.getItem("solState");
      if(!state) {
        sol.homeUrl = this.homeUrl =
          "https://solside.solid.community/public/"
        sol.idp = this.idp =  "https://solid.community"
        return;
      }
      state = JSON.parse(state)
      sol.homeUrl = this.homeUrl = state.home
      sol.idp     = this.idp     = state.idp
      this.editKeys  = state.keys
      this.editTheme = state.theme
      fileDisplay.initEditor();
      fileDisplay.setEditTheme(this.editTheme);
      fileDisplay.setEditKeys(this.editKeys);
      return state
    },
    //
    // MAIN PROCESS LOOP, CALLED ON RETURN FROM ASYNC SOLID CALLS
    //
    processResults : function(results){
      if(!results){
        alert( sol.err )
        return
      }
      var key = results.key
      var val = results.value
      if(key.match("folder")){
        app.folder = val
        app.currentThing = val
        if(sol.qname) { 
          app.currentThing = sol.qname
          sol.get(sol.qname).then( results => { 
            if(!results) alert(sol.err)
            app.processResults(results)
          })
        }
        else if(sol.hasIndexHtml) { 
          app.currentThing = {
            url : val.url + "index.html",
            type : "text/html"
          }
          sol.get(app.currentThing).then( results => { 
            if( !results ) alert(sol.err)
            app.processResults(results)
          })
        }
      }
      if( val.type.match(/(image|audio|video)/)  ){
        val.content=""
      }
      fileDisplay.setContent(val.content) 
      fileDisplay.file.srcUrl = app.currentThing.url
      sol.checkStatus(val.url).then( status => {
        var url = location.href.replace(/^[^\?]*\?/,'')
        var url2 = location.href.replace(url,'').replace(/\?$/,'')  
        if(url2) {
          url2 = url2  + "?url="+encodeURI(val.url)
        }
        history.pushState({s:2,b:1},"solside",url2)
        app.getLogState(status)
        view.modUI(status,val.type)
      }, err => { console.log(err)})
    }, /* process results */

  }, /* methods */
  data: { 
    fontSize     : "medium",
    editKeys     : "emacs",
    editTheme    : "dark theme",
    perms        : {},
    currentThing : {},
    newThing     : {},
    file         : {},
    folder       : { name:'loading...' },
    idp          : "",
    homeUrl      : "",
    webId        : "",
    logState     : "login",
    loggedIn     : false,
    nixPass      : "",
    nixPassErr   : "",
    nixLoaded    : false,
  }, /* data */
}) /* app */

var view = {
  currentForm : "",
  show : function(area){
    this.currentForm = this.currentForm || area;
    var x = document.getElementById(this.currentForm)
    document.getElementById(this.currentForm).style.display = 'none'; 
    this.currentForm = area;
    document.getElementById(area).style.display = 'block'; 
    document.getElementById('fileDisplay').style.display = 'none'; 
  },
  hide : function(area){
    document.getElementById('fileDisplay').style.display = 'block'; 
    area = area || this.currentForm;
    if(area)
      document.getElementById(area).style.display = 'none'; 
  },
  modUI : function(status,type){
    var saveButton    = document.getElementById('saveEdits')
    var optionsButton = document.getElementById('optionsButton')
    var profileButton = document.getElementById('profileButton')
    var editDisabled = document.getElementById('editDisabled')
    saveButton.style.display="none"
    optionsButton.style.backgroundColor="#ddd"
    profileButton.style.display="none"
    editDisabled.style.display="table-cell"
    if(status.loggedIn) {
      optionsButton.style.backgroundColor = "rgba(145,200,220,2)";
      profileButton.style.display="inline-block"
      if( status.permissions.Write 
        && !type.match(/(image|audio|video|folder)/)
      ){
        saveButton.style.display = 'table-cell'
        saveButton.style.backgroundColor = "rgba(145,200,220,2)"
        editDisabled.style.display="none"
      }
    }
  }
}

init()

