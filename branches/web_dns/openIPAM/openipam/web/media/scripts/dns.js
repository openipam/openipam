
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
	//create list
	submitList = [];
	
	//loop through existing rows
	rows = $('tr.info').each(function(){		
		var temp_record = new Object();
		
		temp_record.id = $(this).attr('id');

		if($(this).find('input[name="delete"]:checked').val()){
			temp_record.deleted = true;
		}
		else{
			var name = $(this).find('input[name="name"]').val();
			temp_record.name = name;
			temp_record.tid = $(this).find('select[name="tid"]').val();
			var content = $(this).find('input[name="content"]').val();
			temp_record.content = content;
		}
		
		if(temp_record.deleted || (name || content)){
			submitList.push(temp_record);
		}
		
	}); //end rows loop
	
	//loop through new rows
	newRows = $('tr.infoNew').each(function(){
		new_record = {};
		
		if($(this).find('input[name="no_add"]:checked').val()){
			new_record['no_add'] = true;
		}
		else{
			var name = $(this).find('input[name="name"]').val();
			new_record['name'] = name;
			new_record['tid'] = $(this).find('select[name="tid"]').val();
			var content = $(this).find('input[name="content"]').val();
			new_record['content'] = content;
		}
		
		if((name || content) && !new_record['no_add']){
			submitList.push(new_record);
		}
		
	}); // end newRows loop
	
	console.log(submitList);
	
	//sent list to webservice
	$.ajax({
		url: "/ajax/ajax_change_dns_records",
		data: { 'json' : JSON.stringify(submitList) },
		success: function(){
			//alert("Success");
		}
	});
	
	return false;
};


$(function() {
	//bind to a key
	$('#saveRecords').click( saveRecords );
	
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
	
	names = [];
	
	/*
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
	*/
	
});
