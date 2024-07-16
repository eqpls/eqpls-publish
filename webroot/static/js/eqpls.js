// javascript here

Auth.init((auth)=> {
	console.log(auth.RestHeaders);
	fetch("/secret/test/case1", {
		headers: auth.RestHeaders
	}).then((res)=> {
		if (!res.ok) { throw res; }
		return res.text()
	}).then((data)=> {
		console.log(data);
	});
});