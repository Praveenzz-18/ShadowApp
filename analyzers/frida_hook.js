/**
 * analyzers/frida_hook.js - ShadowApp Frida Dynamic Instrumentation Hook
 *
 * Injected into the target Android process during sandbox execution.
 * Hooks sensitive runtime APIs and streams structured JSON events back via send().
 */

'use strict';

Java.perform(function () {
  console.log('[ShadowApp Frida] Runtime instrumentation initialized.');

  function emitTelemetry(category, apiName, metadata) {
    var payload = {
      timestamp: new Date().toISOString(),
      category: category,
      api: apiName,
      metadata: metadata || {}
    };
    send(JSON.stringify(payload));
  }

  // 1. Hook SmsManager.sendTextMessage (Premium SMS Toll Fraud)
  try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.overload(
      'java.lang.String',
      'java.lang.String',
      'java.lang.String',
      'android.app.PendingIntent',
      'android.app.PendingIntent'
    ).implementation = function (destAddr, scAddr, text, sentIntent, deliveryIntent) {
      emitTelemetry('TELEPHONY', 'android.telephony.SmsManager.sendTextMessage', {
        destination: destAddr,
        messageLength: text ? text.length : 0,
        textPreview: text ? text.substring(0, 40) : ''
      });
      return this.sendTextMessage(destAddr, scAddr, text, sentIntent, deliveryIntent);
    };
  } catch (err) {
    console.log('[Frida Warning] SmsManager hook failed: ' + err);
  }

  // 2. Hook LocationManager.getLastKnownLocation & requestLocationUpdates (Geolocation Surveillance)
  try {
    var LocationManager = Java.use('android.location.LocationManager');
    LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
      emitTelemetry('LOCATION', 'android.location.LocationManager.getLastKnownLocation', {
        provider: provider
      });
      return this.getLastKnownLocation(provider);
    };
  } catch (err) {
    console.log('[Frida Warning] LocationManager hook failed: ' + err);
  }

  // 3. Hook ContentResolver.query (Data Harvesting: Contacts, SMS, Call Logs)
  try {
    var ContentResolver = Java.use('android.content.ContentResolver');
    var Uri = Java.use('android.net.Uri');

    ContentResolver.query.overload(
      'android.net.Uri',
      '[Ljava.lang.String;',
      'java.lang.String',
      '[Ljava.lang.String;',
      'java.lang.String'
    ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
      var uriStr = uri ? uri.toString() : '';
      if (
        uriStr.indexOf('contacts') !== -1 ||
        uriStr.indexOf('sms') !== -1 ||
        uriStr.indexOf('call_log') !== -1
      ) {
        emitTelemetry('CONTENT_RESOLVER', 'android.content.ContentResolver.query', {
          uri: uriStr,
          projection: projection ? projection.toString() : 'ALL'
        });
      }
      return this.query(uri, projection, selection, selectionArgs, sortOrder);
    };
  } catch (err) {
    console.log('[Frida Warning] ContentResolver hook failed: ' + err);
  }

  // 4. Hook DexClassLoader & PathClassLoader (Hidden Payload / Dropper Detection)
  try {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function (dexPath, optDir, libSearchPath, parent) {
      emitTelemetry('DYNAMIC_CODE_LOADING', 'dalvik.system.DexClassLoader.$init', {
        dexPath: dexPath,
        optimizedDirectory: optDir
      });
      return this.$init(dexPath, optDir, libSearchPath, parent);
    };

    DexClassLoader.loadClass.overload('java.lang.String').implementation = function (className) {
      emitTelemetry('DYNAMIC_CODE_LOADING', 'dalvik.system.DexClassLoader.loadClass', {
        className: className
      });
      return this.loadClass(className);
    };
  } catch (err) {
    console.log('[Frida Warning] DexClassLoader hook failed: ' + err);
  }

  // 5. Hook Runtime.exec (Arbitrary Root Shell Execution)
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      emitTelemetry('SYSTEM_EXEC', 'java.lang.Runtime.getRuntime.exec', {
        command: cmd
      });
      return this.exec(cmd);
    };
  } catch (err) {
    console.log('[Frida Warning] Runtime.exec hook failed: ' + err);
  }

  // 6. Universal SSL Pinning Bypass (for mitmproxy interception)
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function () {
      emitTelemetry('NETWORK_SECURITY', 'SSL_PINNING_BYPASS', {
        status: 'Certificate check bypassed for dynamic interception'
      });
      return Java.use('java.util.ArrayList').$new();
    };
  } catch (err) {
    // SSL Pinning hook might vary by Android OS version
  }
});
