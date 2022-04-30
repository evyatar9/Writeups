Java.perform(function() {

	
	let MainActivity = Java.use("com.example.clickme.MainActivity");
	
	MainActivity.getFlagButtonClick.implementation = function(view){
	this.CLICKS.value = 99999999;
    console.log('getFlagButtonClick is called');
    let ret = this.getFlagButtonClick(view);
    console.log('getFlagButtonClick ret value is ' + ret);
    return ret;
};


}, 0);