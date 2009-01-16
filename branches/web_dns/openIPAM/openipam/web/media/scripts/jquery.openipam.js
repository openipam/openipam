/*
 * The bizom openIPAM front-end DOM manipulation and AJAX thingy
 */

;(function($) {
	/*
	 * Error
	 * 
	 * Display the error message.
	 */

	openipam = {
		error: function(event, XMLHttpRequest, ajaxOptions, thrownError) {
			$('<div>There was an error in requesting the information. Please tell the openIPAM developers about this error.<br /><br />' + XMLHttpRequest.responseText + '</div>')
				.appendTo($(this));
					
			$(this).slideDown(1000);
			
			if (window.console && window.console.error) {
				console.error(arguments);
				console.error(event);
		    }
		    
		    return false;
		}
	}

	$.ajaxSetup({
	  type: "POST",
	  dataType: "json"
	});

	$.openipam = {
			init: function() {
				// Add the error listener
				$('#globalMessage').ajaxError(openipam.error);
			}
	}
	
	$.openipam.error = function(message) {
			$('<div>'+message+'</div>').appendTo($('#globalMessage'));
			$('#globalMessage').slideDown(1000);
			
			if (window.console && window.console.error) {
				console.error(arguments);
			}
	}

})(jQuery);