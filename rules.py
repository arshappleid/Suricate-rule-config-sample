## Done - Tested
alert http any any -> any any (
    msg:"Botnet";
	http_method; content:"POST";
	http_uri; content:"/api/Administrator_";
    sid:1001;
    rev:5;
)
## Done - Tested
alert tcp 13.58.98.0/24 any -> 172.31.69.0/24 22 (
    msg:"Bruteforce";
    detection_filter:track by_src, count 400, seconds 1;
    sid:2001;
    rev:13;
)

## Done - Tested
alert http any any -> 172.31.69.0/24 80 (
    msg:"WebAttack";
    flow:to_server,established;
    http_method; content: "POST"; 
	http_uri; content: ".php";
    sid:3001;
    rev:10;
)

## Done - Tested
alert http 18.219.211.0/24 30000:60000 -> 172.31.69.0/24 80 (
    msg:"DdoS";
    dsize:>100;
	flow:to_server,established;
	detection_filter:track by_src, count 300, seconds 1;
	http_method; content:"GET";
	sid:4001;
	rev:28;
)