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
			
			fault = XMLHttpRequest.responseXML.documentElement.textContent
			if (fault.indexOf("<Fault 1: '[ListXMLRPCFault] ") != -1) {
				// Have a ListXMLRPCFault
				start = fault.indexOf("<Fault 1: '[ListXMLRPCFault] ")+"<Fault 1: '[ListXMLRPCFault] ".length;
				faultLength = fault.indexOf("'>") - start;
				faultString = fault.substr(start, faultLength);
				errors = faultString.split(";");
				for (i in errors) {
					errors[i] = '<li>' + errors[i] + '</li>';
				};
				$(this).html('<div>The following errors occurred:<br /><br /><ul>' + errors.join('') + '</ul></div>');
			} else {
				$('<div>There was an error in requesting the information. Please tell the openIPAM developers about this error.<br /><br />' + XMLHttpRequest.responseText + '</div>').appendTo($(this));
			};
			
			$(this).slideDown(1000);
			
			if (window.console && window.console.error) {
				//console.log(event);
				/*console.error(fault);
				console.error(ajaxOptions);
				console.error(thrownError);
				console.error(arguments);
				console.error(event);*/
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