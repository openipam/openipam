
function deleteChecked(i, k) {
	deleteEl = document.getElementById('deleteRow' + i);
	
	disabledState = false;
	if( deleteEl.checked ) {
		disabledState = true;
	}

	nameEl = document.getElementById('name' + i);
	ttlEl = document.getElementById('ttl' + i);
	typeEl = document.getElementById('type' + i);
	textEl = document.getElementById('text' + i);
	
	nameEl.disabled = disabledState;
	ttlEl.disabled = disabledState;
	typeEl.disabled = disabledState;
	textEl.disabled = disabledState;

};

function saveRecords() {
	//bind to a key
	$('#saveRecords').click();
	//create list
	submitList = [];
	//loop through rows
	temp = $('.info').find(name);
	console.log(temp);
		//create dictionary inside row
		//add data to dictionary using the id as the key and the content as the value
		//add deleted flag
	//sent list to webservice
};


$(function() {
	var counter = 0;	
	$('tr.infoNew').hide();
	$('#addRecord').click(function(){
		$('tr#new' + ++counter).show();
		$('tr#new' + counter + ' input.name').focus();
		
		
		/*$('#test').click(function (){
			//$(".autocomplete").autocomplete("flushCache");
			$(".autocomplete").autocomplete({data: ['new', 'list']});
		});
		
		$('.autocomplete').keyup(function (){
			
			$(".autocomplete").autocomplete("search");
		});*/
	});
	if($('#quickAdd').length){
		$('#addRecord').click();
	};
	
	var temp = $('tr.info').find(name);
	console.log('hello');
	console.log(temp);
	
	names = [];
	
	$.ajax({
		url: "/ajax/ajax_get_domains/",
		data: { additional_perms : '00000010' },
		success: function(response){
			for(i in response){
				names.push(response[i]['name']);
			}
			
			$(".autocomplete").autocomplete({ 
			    data: names 
			});
		}
	});
	
});
