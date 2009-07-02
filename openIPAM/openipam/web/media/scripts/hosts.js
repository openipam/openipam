
/*
 * Add Host
 */

/*
*/
function toggleIPField(){
	$("#ipContent").slideToggle("fast", function(){
		if (!$("#dynamicIP").attr("checked")) {
			$("#ipContentText").focus();
		} else {
			$("#dynamicIP").focus();
		}
	});
};

function toggleHostFlyout( mac ){
	
	$("#hostInfo" + mac).toggle();
	$("#arrow" + mac).toggleClass("expand");
	$("#arrow" + mac).toggleClass("contract");

	if($("#hostInfo" + mac + ' input.isLoaded').attr('name') == "False") {
		
		position = $("#hostInfo" + mac + ' div.innerHostInfo');
		position.append('<img src="/images/interface/loader.gif" id="loaderIcon" />');
		
		output = [];
		
		$.ajax({
			url: "/ajax/ajax_find_owners_of_host/",
			data: { mac : mac },
			async: false, 
			success: function(response){
				if (response.length){
					owners = [];
					for (i in response){
						owners.push(response[i].name);
					}
					output.push('<strong>Owners:</strong> ' + owners.join(', ') + '<br /><br />');
				}
			}
		});
		
		$.ajax({
			url: "/ajax/ajax_get_dns_records/",
			data: { mac : mac, order_by : 'tid, ip_content, name' },
			async: false, 
			success: function(response) {
				var hasIP = false;
				var row = null;
				
				for (i in response) {
					if (response[i].tid == 1) {
						output.push('<strong>IP:</strong> ' + response[i].ip_content + ' &mdash; ' + response[i].name+'<br />');
						hasIP = true;
					}
					else if (response[i].tid == 5) {
						output.push('<strong>CNAME:</strong> ' + response[i].name + ' &mdash; ' + response[i].text_content + '<br />');
					}
					else if (response[i].tid == 12) {
						output.push('<strong>PTR:</strong> ' + response[i].name + ' &mdash; ' + response[i].text_content + '<br />');
					}
					else if (response[i].tid == 15) {
						output.push('<strong>MX:</strong> ' + response[i].name + ' &mdash; ' + response[i].priority + ' ' + response[i].text_content + '<br />');
					}
					else if (response[i].tid == 33) {
						output.push('<strong>SRV:</strong> ' + response[i].name + ' &mdash; ' + response[i].priority + ' ' + response[i].text_content + '<br />');
					}
				}
				if (!hasIP) {
					output.push('<strong>IP:</strong> dynamic<br />');
				}
				$("#hostInfo" + mac + " div.innerHostInfo #loaderIcon").remove();
				position.append(output.join(''));
			}
		});
		$("#hostInfo" + mac + ' input.isLoaded').attr('name', "True");
		
	}
};

/*
 * Managing contacts on hosts
 */
 
function addOwner(ownerName) {
	$('#owners_list').val($('#owners_list').val()+ownerName+',');

	addOwnerToRow(ownerName);	
}

function addOwnerToRow(ownerName) {
	$('#currentOwners').append('<tr id="'+ownerName+'" class="info"><td>'+ownerName+'</td><td class="actions"><a id="removeOwner" href="javascript:;">Remove</a></td></tr>');
	$('#currentOwners tr[id="'+ownerName+'"] td #removeOwner').click(function () {
		removeOwner($('#currentOwners tr[id="'+ownerName+'"]').attr('id'));
	});
}
			
function removeOwner(ownerName) {
	$('#owners_list').text($('#owners').text().replace(ownerName+',', ''));
	$('#currentOwners tr[id="'+ownerName+'"]').remove();
	$('#owners_list').val($('#owners_list').val().replace(ownerName+',', ''));
}

function updateOwnersList() {
	var owner = null;
	var owners_list = $('#owners_list').val().split(',');
	
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

/*
 * Global
 */

$(function() {
	if ($("#dynamicIP").attr("checked")) {
		$("#ipContent").hide();
	};
	
	$('#expirationContent').hide();
	
	/* Listeners */
	
	$("#submitSearch").click(function () {
		$('#loaderIcon').show();
	});
	
	$('.toggleHostFlyout').click(function () {
		toggleHostFlyout($(this).attr('name'));
		$(this).blur()
	});
	
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
				    height: 500,
				    width: 700, 
				    overlay: { 
				        opacity: 0.5, 
				        background: "black" 
				    	}
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
	
	// For the initial groups that are shown
	if ($("#group_dialog").length) {
		full_group_list = $('#full_group_list').val().split("-*-");
		showGroups();
	}
	
	if ($('input[name="old_mac"]').length) {
		// We're editing a host

		$('#ipContent').hide();
		
		var checkbox = $("#dynamicIP");
		
		if (!checkbox.attr("checked")) {
			checkbox.click(function () {
				var checkbox = $("#dynamicIP");
				
				$('#currentIPContent').css( { textDecoration : 'line-through' });
				
				if (checkbox.attr("checked")) {
					alert("By moving this host from static to dynamic, all DNS resource records will be irreversibly lost (including any A records, CNAMEs, MX records, etc.)\n\nThis action cannot be undone.\n\nIf you do not want this to happen, uncheck Dynamic IP Address.")
				} else {
					$('#currentIPContent').css( { textDecoration : 'none' });
				}
			});
		}
	}
	
	if (!$('input[name="did_not_change_ip"]').length) {
		// We're not editing a static host
		$('#dynamicIP').click(function () {
			toggleIPField();
		});
	}
	
	
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
		$("#ipContent").slideToggle("fast");
		
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
	
	$('#searchBox').focus();

	$("#selectAll").click(function() {
		if ($(this).attr("checked")) {
			$("input[name='multihosts']").attr("checked", true);
		} else {
			$("input[name='multihosts']").attr("checked", false);
		}
	});
	
});
