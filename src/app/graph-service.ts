// ------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
// ------------------------------------------------------------------------------

import { Injectable } from '@angular/core';
import { Http, Response, ResponseContentType, Headers } from '@angular/http';

import { RequestType, AllowedGraphDomains } from "./base";
import 'rxjs/add/operator/toPromise';
//import {readFile} from "@node/node";
/*
import {passport} from 'passport'

var creds = {
    // Required
    identityMetadata: 'https://login.microsoftonline.com/microsoft.onmicrosoft.com/.well-known/openid-configuration', 
    // or equivalently: 'https://login.microsoftonline.com/<tenant_guid>/.well-known/openid-configuration'
    //
    // or you can use the common endpoint
    // 'https://login.microsoftonline.com/common/.well-known/openid-configuration'
    // To use the common endpoint, you have to either set `validateIssuer` to false, or provide the `issuer` value.
  
    // Required, the client ID of your app in AAD  
    clientID: '35574b15-d5ef-43a9-96e5-0a4574d4c352',
  
    // Required, must be 'code', 'code id_token', 'id_token code' or 'id_token' 
    responseType: 'code id_token', 
  
    // Required
    responseMode: 'form_post', 
  
    // Required, the reply URL registered in AAD for your app
    redirectUrl: 'http://localhost:3000/auth/openid/return', 
  
    // Required if we use http for redirectUrl
    allowHttpForRedirectUrl: true,
    
    // Required if `responseType` is 'code', 'id_token code' or 'code id_token'. 
    // If app key contains '\', replace it with '\\'.
    clientSecret: 'qF49Z6t0+F0T1oGBRNB51+J24eT7q4WrjXY0BS21ce8=', 
  
    // Required to set to false if you don't want to validate issuer
    validateIssuer: true,
    
    // Required to set to true if you are using B2C endpoint
    // This sample is for v1 endpoint only, so we set it to false
    isB2C: false,
  
    // Required if you want to provide the issuer(s) you want to validate instead of using the issuer from metadata
    issuer: null,
  
    // Required to set to true if the `verify` function has 'req' as the first parameter
    passReqToCallback: false,
  
    // Recommended to set to true. By default we save state in express session, if this option is set to true, then
    // we encrypt state and save it in cookie instead. This option together with { session: false } allows your app
    // to be completely express session free.
    useCookieInsteadOfSession: true,
  
    // Required if `useCookieInsteadOfSession` is set to true. You can provide multiple set of key/iv pairs for key
    // rollover purpose. We always use the first set of key/iv pair to encrypt cookie, but we will try every set of
    // key/iv pair to decrypt cookie. Key can be any string of length 32, and iv can be any string of length 12.
    cookieEncryptionKeys: [ 
      { 'key': '12345678901234567890123456789012', 'iv': '123456789012' },
      { 'key': 'abcdefghijklmnopqrstuvwxyzabcdef', 'iv': 'abcdefghijkl' }
    ],
  
    // Optional. The additional scope you want besides 'openid', for example: ['email', 'profile'].
    scope: null,
  
    // Optional, 'error', 'warn' or 'info'
    loggingLevel: 'info',
  
    // Optional. The lifetime of nonce in session or cookie, the default value is 3600 (seconds).
    nonceLifetime: null,
  
    // Optional. The max amount of nonce saved in session or cookie, the default value is 10.
    nonceMaxAmount: 5,
  
    // Optional. The clock skew allowed in token validation, the default value is 300 seconds.
    clockSkew: null,
  };
  
  // Optional.
  // If you want to get access_token for a specific resource, you can provide the resource here; otherwise, 
  // set the value to null.
  // Note that in order to get access_token, the responseType must be 'code', 'code id_token' or 'id_token code'.
  //exports.resourceURL = 'https://graph.windows.net';
  var resourceURL = 'https://management.core.windows.net/';
  
  // The url you need to go to destroy the session with AAD
  var destroySessionUrl = 'https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=http://localhost:3000';
  


var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
//-----------------------------------------------------------------------------
// To support persistent login sessions, Passport needs to be able to
// serialize users into and deserialize users out of the session.  Typically,
// this will be as simple as storing the user ID when serializing, and finding
// the user by ID when deserializing.
//-----------------------------------------------------------------------------
passport.serializeUser(function(user, done) {
    done(null, user.oid);
  });
  
  passport.deserializeUser(function(oid, done) {
    findByOid(oid, function (err, user) {
      done(err, user);
    });
  });
  
  // array to hold logged in users
var users = [];

var findByOid = function(oid, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
   console.log('we are using user: ', user);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

var access_token = "";
var refresh_token = "";

//-----------------------------------------------------------------------------
// Use the OIDCStrategy within Passport.
// 
// Strategies in passport require a `verify` function, which accepts credentials
// (in this case, the `oid` claim in id_token), and invoke a callback to find
// the corresponding user object.
// 
// The following are the accepted prototypes for the `verify` function
// (1) function(iss, sub, done)
// (2) function(iss, sub, profile, done)
// (3) function(iss, sub, profile, access_token, refresh_token, done)
// (4) function(iss, sub, profile, access_token, refresh_token, params, done)
// (5) function(iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
// (6) prototype (1)-(5) with an additional `req` parameter as the first parameter
//
// To do prototype (6), passReqToCallback must be set to true in the config.
//-----------------------------------------------------------------------------
passport.use(new OIDCStrategy({
    identityMetadata: creds.identityMetadata,
    clientID: creds.clientID,
    responseType: creds.responseType,
    responseMode: creds.responseMode,
    redirectUrl: creds.redirectUrl,
    allowHttpForRedirectUrl: creds.allowHttpForRedirectUrl,
    clientSecret: creds.clientSecret,
    validateIssuer: creds.validateIssuer,
    isB2C: creds.isB2C,
    issuer: creds.issuer,
    passReqToCallback: creds.passReqToCallback,
    scope: creds.scope,
    loggingLevel: creds.loggingLevel,
    nonceLifetime: creds.nonceLifetime,
    nonceMaxAmount: creds.nonceMaxAmount,
    useCookieInsteadOfSession: creds.useCookieInsteadOfSession,
    cookieEncryptionKeys: creds.cookieEncryptionKeys,
    clockSkew: creds.clockSkew,
  },
  function(iss, sub, profile, accessToken, refreshToken, done) {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByOid(profile.oid, function(err, user) {
        if (err) {
          return done(err);
        }
        console.log("accessToken :", accessToken )
        console.log("refreshToken :", refreshToken )
        access_token = accessToken;
        refresh_token = refreshToken;
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        }
        return done(null, user);
      });
    });
  }
));

*/
import {Observable} from 'rxjs/Rx';
  

@Injectable()
export class GraphService {
  constructor (private http: Http) {}
  public access_token: string;
  
  performAnonymousQuery(queryType:RequestType, query:string, headers?:Headers):Promise<Response> {
        if (!headers) {
            headers = new Headers();
        }
        headers.append("Authorization", "Bearer {token:https://graph.microsoft.com/}");

        if (queryType === "GET") {
            return this.http.get(`https://proxy.apisandbox.msdn.microsoft.com/svc?url=${encodeURIComponent(query)}`, {headers}).toPromise();
        } else if (queryType === "GET_BINARY") {
            return this.http.get(`https://proxy.apisandbox.msdn.microsoft.com/svc?url=${encodeURIComponent(query)}`, {headers, responseType: ResponseContentType.ArrayBuffer}).toPromise();
        }
    }
        // let method = isAuthenticated() ? this.GraphService.performQuery : this.GraphService.performAnonymousQuery;

    performQuery = (queryType:RequestType, query:string, postBody?:any, requestHeaders?:Headers) => {
        // make sure the request is being sent to the Graph and not another domain
        let sentToGraph = false;

        for (let domain of AllowedGraphDomains) {
            if (query.startsWith(domain)) {
                sentToGraph = true;
                break;
            }
        }

        if (!sentToGraph) {
            throw "Not sending request to known Graph deployment";
        }

        if (typeof requestHeaders === "undefined") {
            requestHeaders = new Headers();
        }

        //var tokenResp = this.getData(); // this.http.get("http://localhost:30001/token").toPromise().then(response => response.json);
        console.log("tokenResp: " + this.access_token);        
                          
        if(query.startsWith("https://management.azure.com")) {
            
            requestHeaders.append("Authorization", `Bearer ` + this.access_token)
        }
        else {
            var authResp = hello.getAuthResponse('msft');
            console.log("AuthResponse: " + JSON.stringify(authResp))                       
            requestHeaders.append("Authorization", `Bearer ${authResp.access_token}`)
        }


        switch(queryType) {
            case "GET":
                return this.http.get(query, {headers: requestHeaders}).toPromise();
            case "GET_BINARY":
                return this.http.get(query, {responseType: ResponseContentType.ArrayBuffer, headers : requestHeaders}).toPromise();
            case "PUT":
                return this.http.put(query, postBody, {headers : requestHeaders}).toPromise();
            case "POST":
                return this.http.post(query, postBody, {headers : requestHeaders}).toPromise();
            case "PATCH":
                return this.http.patch(query, postBody, {headers : requestHeaders}).toPromise();
            case "DELETE":
                return this.http.delete(query, {headers : requestHeaders}).toPromise();
        }
    }

    getMetadata = (graphUrl:string, version:string) => {
        return this.http.get(`${graphUrl}/${version}/$metadata`).toPromise();
    }
};