
/*
 * Add Host
 */

/*
*/

function loadAddresses() {
			var atype = $('#address_type');
			var adiv = $('#ipContent');
			if ( atype.val() == 'dynamic' ) {
				adiv.hide();
			} else {
				adiv.show();
			}

			var property = '#networks_'+atype.val();
			var jsonstr = $(property).val();

			var nets = $.parseJSON( jsonstr	);

			var abox = $("#network_selection");
			
			var selections = "<option value=''>Please select a network</option>\n";

			for (n in nets) {
				var net = nets[n]
				selections += "<option value='" + net[0] + "'>" + net[0] + ' - ' + net[1] + '</option>\n';
			}

			abox.html(selections);
}


function attribute_form_init() {
	var add_attr_form = "div.add_attribute form";
	$(add_attr_form + " input.add_attribute_fv").hide();
	$(add_attr_form + " select.add_attribute_sv").hide();
	
	$(add_attr_form + " select.add_attribute_type_id").change(function () {
		var add_attr_form = "div.add_attribute form";
		var tselected = add_attr_form + " select.add_attribute_type_id option:selected";
		var fv = add_attr_form + " input.add_attribute_fv";
		var sv = add_attr_form + " select.add_attribute_sv";

		if ($(tselected).attr("class") == "structured") {
			$(fv).hide();
			$(sv).show();
			/* FIXME: load values */
			$.ajax({
				url: "/ajax/ajax_get_structured_attribute_values/",
				data: { aid : $(tselected).val() },
				success: function(data) {
					var html = '<option value="">Select value</option>\n';
					for ( svinfo in data ) {
						html += '<option value="' + data[svinfo].id + '">' + data[svinfo].value + '</option>\n';
					}
					$(sv).html(html)
				}
			});
		} else {
			$(fv).show();
			$(sv).hide();
		}

	});
}

function toggleHostFlyout( mac ){
	
	$("#hostInfo" + mac).toggle();
	$("#arrow" + mac).toggleClass("expand");
	$("#arrow" + mac).toggleClass("contract");

	if($("#hostInfo" + mac + ' input.isLoaded').attr('name') == "False") {
		position = $("#hostInfo" + mac + ' div.innerHostInfo');
		position.append('<img src="/images/interface/loader.gif" id="loaderIcon" />');

		$.ajax( { url: '/hosts/host_info/', data: { mac: mac, wrap: "False"}, dataType: "html",
			       	success: function(data){
					var content = $("#hostInfo" + mac + ' div.innerHostInfo');
					content.html(data);
					$("#hostInfo" + mac + ' input.isLoaded').attr('name', "True");

					$('a.show_add').click( function() {
						addAttributeForm(mac);
						return false;
					});
					
					$('table#attributes_'+mac+" a.delete_value").click( function() {
						var href = $(this).attr("href");
						$.ajax( { url: href, dataType: "html" } );

						$("#hostInfo" + mac + ' input.isLoaded').attr('name', "False");
						$("#hostInfo" + mac).hide();
						toggleHostFlyout(mac);

						return false;
					});
	
				}
			});

	}

};

/*
 * Managing contacts on hosts
 */
 
function addOwner(ownerName) {
	$('#owners_list').val($('#owners_list').val()+ownerName+'|');

	addOwnerToRow(ownerName);	
}

function addOwnerToRow(ownerName) {
	$('#currentOwners').append('<tr id="'+ownerName+'" class="info"><td>'+ownerName+'</td><td class="actions"><a id="removeOwner" href="javascript:;">Remove</a></td></tr>');
	$('#currentOwners tr[id="'+ownerName+'"] td #removeOwner').click(function () {
		removeOwner($('#currentOwners tr[id="'+ownerName+'"]').attr('id'));
	});
}
			
function removeOwner(ownerName) {
	$('#owners_list').text($('#owners').text().replace(ownerName+'|', ''));
	$('#currentOwners tr[id="'+ownerName+'"]').remove();
	$('#owners_list').val($('#owners_list').val().replace(ownerName+'|', ''));
}

function updateOwnersList() {
	var owner = null;
	var owners_list = $('#owners_list').val().split('|');
	
	for ( i in owners_list ) {
		if (owners_list[i] != '') {
			addOwnerToRow(owners_list[i]);
		}
	}
}

function bindAddAsOwner() {
	$('.addOwner').click(function () {
		addOwner(this.name);
		$('#ownersToAdd tr:has(td.actions a.addOwner[name="'+this.name+'"])').html('<td>'+this.name+'</td><td class="actions">Done</td>');
	});
}

function addGroupRow(name) {
	$('#ownersToAdd').append('<tr class="info"><td>'+name+'</td><td class="actions"><a class="addOwner" name="'+name+'" href="javascript:;">Add as owner</a></td></tr>');
}

function showGroups() {
	$('#ownersToAdd').html('');
	for (i in full_group_list) {
		addGroupRow(full_group_list[i]);
	}
	bindAddAsOwner();
}

function addAttributeForm(mac) {

	$.ajax( { url: '/hosts/add_attribute/', data: { mac: mac, wrap: "False"}, dataType: "html",
		success: function (data) {
			var content = $("div#modal-form");
			content.html(data);
			if(data != '') {
				content.dialog( {
					height: 200,
					width: 600,
					modal: true,
					title : 'Add host attribute for '+mac,
					buttons: {
						"Add attribute": function() {
							var formid = "div#add_attribute_"+mac + " form.add_attribute_form";
							var aid = $(formid + " .add_attribute_type_id");
							var avid = $(formid + " .add_attribute_sv");
							var value = $(formid + " .add_attribute_fv");

							$.ajax( { url: '/hosts/add_attribute/',
								data: { mac: mac, wrap: "False",
									attr_type_id: aid.val(),
									freeform_value: value.val(),
									structured_value: avid.val(),
									submit: "Submit"
								},
								dataType: "html",
								success: function(data) {
									$("#modal-form").dialog("close");
									// update the host info
									$("#hostInfo" + mac + ' input.isLoaded').attr('name', "False");
									$("#hostInfo" + mac).hide();
									toggleHostFlyout(mac);
								}
							} );

						},
						Cancel: function() {
							$(this).dialog("close");
						}
					}
				});

				var formid = "div#add_attribute_"+mac + " form.add_attribute_form";
				$(formid).submit( function() {
						/* FIXME: click the button in the modal pane here */
						var buttons = $(this).closest("div.ui-dialog").find("div.ui-dialog-buttonpane div.ui-dialog-buttonset button.ui-button");

						/*
						alert(buttons);


						for ( i in buttons ) {
							alert(i);
							if ( buttons[i].html().indexOf("Add attribute") >= 0 )
							{
								//alert( buttons[i].html() );
								buttons[i].click();
								break;		
							}
						}
						*/

						return false;
				} );

				attribute_form_init();
				content.show();
			}
		}
	});

	return false;
}

/*
 * Global
 */

$(function() {
	if ($("#address_type").val() == 'dynamic') {
		$("#ipContent").hide();
	};
	
	$('#expirationContent').hide();
	
	/* Listeners */
	
	$("#submitSearch").click(function () {
		$('#loaderIcon').show();
	});

	$('a.toggleHostFlyout').click(function () {
		toggleHostFlyout($(this).attr('name'));
		$(this).blur();
	});

	// For the initial groups that are shown
	if ($("#group_dialog").length) {
		full_group_list = $('#full_group_list').val().split("-*-");
		showGroups();
	}
	
	$("#group_dialog").show().dialog({ 
				    modal: true,
				    autoOpen : false,
				    buttons: {
						/*
				    	' Cancel ' : function() {
			    			$("#group_dialog").dialog("close");
			    		},
			    		*/
				    	' Apply ' : function() {
				    		var owners = $('#owners_list').val()
			    			$("#owners").text(owners.substr(0, owners.length-1));
			    			$("#group_dialog").dialog("close");
			    		}
				    },
				    title : 'Manage contact groups',
				    height: 525,
				    width: 700 
    });

	$('#currentOwners tr td #removeOwner').click(function () {
		removeOwner($('#currentOwners tr').attr('id'));
	});
	
	$('#searchHelpIcon').click(function () {
		$('#searchHelp').toggle();
		this.blur();
	});
	
	$('#currentOwners tr td #removeOwner').click(function () {
		removeOwner($('#currentOwners tr').attr('id'));
	});
	
	$('#usernameSearch').click(function () {
		$(this).after('<img src="/images/interface/loader.gif" id="loaderIcon" />');
		$('#showGroupsAgain').show();
		$.ajax({
			url: "/ajax/ajax_get_groups/",
			data: { name : 'user_'+$('#username').val() },
			success: function(data) {
				if (data == '') {
					$('#ownersToAdd').text("");
					$('#searchMessage').text("Could not find any user by that name.").show();
				} else {
					$('#ownersToAdd').text("");
					$('#searchMessage').text("").hide();
					
					// can't do .text here for some reason
					addGroupRow(data[0].name);
					bindAddAsOwner();
				}
				$("#loaderIcon").remove();
			}
		});
		return false;
	});
	
	$('#showGroupsAgain').click(function () {
		$('#searchMessage').text("").hide();
		$('#showGroupsAgain').hide();
		showGroups();
	});
	
	if ($('input[name="old_mac"]').length) {
		// We're editing a host

		$('#ipContent').hide();
		
		var selectbox = $("#address_type");
		
		if (!selectbox.val() == 'dynamic') {
			$('#changeIPLink')(function () {
				var selectbox = $("#address_type");
				
				$('#currentIPContent').css( { textDecoration : 'line-through' });
				
				if (selectbox.val == 'dynamic') {
					alert("By moving this host from static to dynamic, all DNS resource records will be irreversibly lost (including any A records, CNAMEs, MX records, etc.)\n\nThis action cannot be undone.\n\nIf you do not want this to happen, uncheck Dynamic IP Address.")
				} else {
					$('#currentIPContent').css( { textDecoration : 'none' });
				}
			});
		}
	}
	

	if (!$('input[name="did_not_change_ip"]').length) {
		// We're not editing a static host
		$('#address_type').change(loadAddresses);
	}
	
	$("#submitMultiAction").click(function () {
		var actionDropdown = document.getElementsByName("multiaction");
		var actionName = actionDropdown[0].value;
		if (actionName == "delete") {
			if (confirm("Are you sure you want to DELETE ALL of the selected hosts?") && confirm("This will also delete all associated DNS records, and possibly eat your homework.  Also, if you have selected a lot of hosts, it could take a minute.  Are you SURE you're sure?")) {
				return true;
			}
			return false;
		}
		return true;
	});

	$("#multiaction").change(function () {
		var actionDropdown = document.getElementsByName("multiaction");
		var actionName = actionDropdown[0].value;
		if (actionName == "owners") {
			$("#group_dialog").dialog("open");	
		}
	});
	
	
	$('.delHost').click(function () {
		if (confirm("All of this host's DNS resource records will be irreversibly lost (including any A records, CNAMEs, MX records, etc.)\n\nAre you sure want to permanently delete this host?\n"+$('a[name="'+$(this).attr('name')+'"][id="hostLink"]').text()) && confirm("Are you SURE you are sure?")) {
			
			$this = $(this);
			
			$.ajax({
				url: "/ajax/ajax_del_host/",
				data: { mac : $(this).attr('name') },
				success: function(data) {
					$('.infoTable tbody tr#hostRow_'+$this.attr('name')+' + tr.infoExpand').remove();
					$('.infoTable tbody tr#hostRow_'+$this.attr('name')).remove();
				}
			});
			return false;
		}
	});

	$('#renewLink').click(function () {
		$("#expirationContent").slideToggle("fast");
		// Toggle the did_renew_host flag
		
		var input = $('input[name="did_not_renew_host"]');
		
		if (input.length) {
			input.attr('name', 'did_renew_host');
		} else {
			$('input[name="did_renew_host"]').attr('name', 'did_not_renew_host');
		}
	});
		
	$('#groupLink').click(function () {
		$("#group_dialog").dialog("open");	
	});
	
	$('#changeIPLink').click(function () {
		loadAddresses();

		$('#address_type').change(loadAddresses);
		
		var input = $('input[name="did_not_change_ip"]');
		
		if (input.length) {
			input.attr('name', 'did_change_ip');
		} else {
			$('input[name="did_change_ip"]').attr('name', 'did_not_change_ip');
		}
	});
	
	if ($('#owners_list').length) {
		updateOwnersList();
	}

	attribute_form_init();

	$('#searchBox').focus();
	$('#mac').focus();

	$("#selectAll").click(function() {
		if ($(this).attr("checked")) {
			$("input[name='multihosts']").attr("checked", true);
		} else {
			$("input[name='multihosts']").attr("checked", false);
		}
	});
	
});
