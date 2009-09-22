/* 
 * Functions for /admin/groups/
 */
 
/*
 * Users
 */
function confirmUserRemove( id ){
	$("#delUser" + id)
		.after('<span id="confirm'+id+'">Are you sure? <a href="" onclick="removeUser('+id+', '+$('input#gid').val()+'); return false;">Yes</a> / <a href="" onclick="restoreUserRemove('+id+'); return false;">No</a></span>')
		.hide(); 
};

function restoreUserRemove( id ) {
	$("#user"+id+" #confirm"+id).remove();
	$("#delUser"+id).show();
};

function removeUser( id ){
	$.ajax({
		url: "/ajax/ajax_del_user_from_group/?uid="+id+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
				$("#user" + id).remove();
			}
	});
};

function addUserToGroup( uid, permissions ){
	$.ajax({
		url: "/ajax/ajax_add_user_to_group/?uid="+uid+"&gid="+$('input#gid').val()+"&permissions="+permissions,
		type: "GET",
		success: function() {
			$("#add" + uid).after('Done').remove();
		}
	});
};

function changePermissions( uid, pstr, pid ) {
	$('.levitipouter').hide();
	$('#add' + uid + ' a.permissionsChange').text(pstr);
	$('#addLink' + uid).attr("onClick", "addUserToGroup("+uid+", '"+pid+"'); return false;");
	return false;
};
/*
 * Domains
 */
 
function confirmDomainRemove( id ){
	$("#delDomain" + id)
		.after('<span id="confirm'+id+'">Are you sure? <a href="" onclick="removeDomain('+id+', '+$('input#gid').val()+'); return false;">Yes</a> / <a href="" onclick="restoreDomainRemove('+id+'); return false;">No</a></span>')
		.hide(); 
};

function restoreDomainRemove( id ) {
	$("#domain"+id+" #confirm"+id).remove();
	$("#delDomain"+id).show();
};

function removeDomain( id ){
	$.ajax({
		url: "/ajax/ajax_del_domain_from_group/?did="+id+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
				$("#domain" + id).remove();
			}
	});
};

function addDomainToGroup( did, pid ){
	$.ajax({
		url: "/ajax/ajax_add_domain_to_group/?did="+did+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
			$("#add" + did).after('Done').remove();
		}
	});
};

/*
 * Networks
 */

function confirmNetworkRemove( id ){
	$("#delNetwork" + id)
		.after('<span id="confirm'+id+'">Are you sure? <a href="" onclick="removeNetwork(\''+id+'\', '+$('input#gid').val()+'); return false;">Yes</a> / <a href="" onclick="restoreNetworkRemove(\''+id+'\'); return false;">No</a></span>')
		.hide(); 
};

function restoreNetworkRemove( id ) {
	$("#network"+id+" #confirm"+id).remove();
	$("#delNetwork"+id).show();
};

function removeNetwork( id ){
	$.ajax({
		url: "/ajax/ajax_del_network_from_group/?nid="+id+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
				$("#network" + id).remove();
			}
	});
};

function addNetworkToGroup( nid, pid ){
	$.ajax({
		url: "/ajax/ajax_add_network_to_group/?nid="+nid+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
			$("#add" + nid).after('Done').remove();
		}
	});
};
/*
 * Hosts
 */
 
function confirmHostRemove( mac ){
	$("#delHost" + mac)
		.after('<span id="confirm'+mac+'">Are you sure? <a href="" onclick="removeHost(\''+mac+'\', '+$('input#gid').val()+'); return false;">Yes</a> / <a href="" onclick="restoreHostRemove(\''+mac+'\'); return false;">No</a></span>')
		.hide(); 
};

function restoreHostRemove( mac ) {
	$("#host"+mac+" #confirm"+mac).remove();
	$("#delHost"+mac).show();
};

function removeHost( mac ){
	$.ajax({
		url: "/ajax/ajax_del_host_from_group/?mac="+mac+"&gid="+$('input#gid').val(),
		type: "GET",
		success: function() {
				$("#host" + mac).remove();
			}
	});
};

function addHostToGroup( mac ){
	$.ajax({
		type: "GET",
		url: "/ajax/ajax_add_host_to_group/?mac="+mac+"&gid="+$('input#gid').val(),
		success: function() {
			$("#add" + mac).after('Done').remove();
		}
	});
};
/*
 * Groups
 */

function delGroupConfirm( gid ){
	$("#del" + gid)
		.after('<span id="confirm'+gid+'">Are you sure? <a href="javascript:;" onclick="delGroup('+gid+'); return false;">Yes</a> / <a href="javascript:;" onclick="restoreDelGroup('+gid+');">No</a></span>')
		.hide(); 
};

function restoreDelGroup( gid ) {
	$("#confirm"+gid).remove();
	$("#del"+gid).show();
};

function delGroup( gid ){
	$.ajax({
		url: "/ajax/ajax_del_group/?gid="+gid,
		type: "GET",
		success: function(data) {
			$("#group" + gid).remove();
		}
	});
};

/* 
 * Functions for /admin/
 */

$(function() {
	$('#search').focus();
	
	$('.permissionsChange').each(function() {
			$(this).leviTip(
			{
				activateOn: 'click',
				sourceType: 'element',
				addClass: '',
				source: 'tr#user' + this.name + ' td.actions #overlayPicker',
				closeDelay: 500,
				leftOffset: -20,
				topOffset: -40
			});
	 	});
});