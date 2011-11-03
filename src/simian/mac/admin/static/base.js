// Copyright 2011 Google Inc. All Rights Reserved.

/**
 * @fileoverview This is the main JavaScript file for the Simian project.
 *
 */

var simian = {};
var applesus = {};


simian.$ = function(id) {
  return document.getElementById(id);
};



/**
 * Focus the search box if it exists.
 */
simian.focusSearch = function() {
  var el = simian.$('search-box');
  if (el) {
    el.focus();
  }
};


/**
 * Toggles Package list Description visibility.
 * @param {Element} a The anchor element that was clicked.
 */
simian.togglePkgDescVisibility = function(a) {
  var descElements = document.getElementsByClassName('pkg-description');
  var hidden = descElements[0].style.display == 'none' ? true : false;
  a.innerHTML = hidden ? 'Hide Descriptions' : 'Show Descriptions';
  for (var i = 0, el; el = descElements[i]; i++) {
    if (hidden) {
      el.style.display = 'inline';
      el.parentNode.firstElementChild.style.display = 'none';
    } else {
      el.style.display = 'none';
      el.parentNode.firstElementChild.style.display = 'inline';
    }
  }
};


/**
 * Toggles a collapsible box between expanded and collapsed.
 * @param {Event} e The onclick event object from the clicked header div.
 */
simian.toggleCollapsible = function(e) {
  // parentNode == main box div, childNodes[3] == content div.
  var div = e.target.parentNode.childNodes[3];
  // TODO(user): finish with images.
  if (div.className.match('collapsed')) {
    div.className = div.className.replace('collapsed', '');
    //img.innerHTML = "<img src=\"images/triangle-open.gif\" />";
  } else {
    div.className = div.className + ' collapsed';
    //img.innerHTML = "<img src=\"images/triangle-closed.gif\" />";
  }
};


/**
 * Initializes collapsible boxes, attaching onclick event handlers to headers.
 */
simian.initCollapsibles = function() {
  var elements = document.getElementsByClassName('collapsible');
  for (var i=0, el; el = elements[i]; i++) {
    var header = el.childNodes[1];  // [0] = TextNode, [1] = header.
    header.onclick = simian.toggleCollapsible;
  }
};


/**
 * XHR function for AJAX requests.
 * @param {string} url String URL to call.
 * @param {string} params URL encoded string of query/POST parameters.
 * @param {string} method HTTP method to use; GET, POST, PUT, etc.
 * @param {function} successCallback Callback function called on success.
 * @param {function} failureCallback Callback function called on failure.
 */
simian.xhr = function(url, params, method, successCallback, failureCallback) {
  var callback = function() {
    if (this.readyState == 4 && this.status == 200) {
      successCallback(this);
    } else if (this.readyState == 4 && this.status != 200) {
      failureCallback(this);
    }
  };
  var client = new XMLHttpRequest();
  client.open(method, url);
  if (method == 'POST') {
    client.setRequestHeader(
        'Content-type', 'application/x-www-form-urlencoded');
  }
  client.onreadystatechange = callback;
  client.send(params);
};


/**
 * Uses XHR to delete a client log file.
 * @param {Element} deleteButton The delete button clicked to call this func.
 */
simian.deleteClientLogFile = function(deleteButton) {
  var key = deleteButton.name;
  var success = function(e) {
    var rowIndex = deleteButton.parentNode.parentNode.rowIndex;
    var table = deleteButton.parentNode.parentNode.parentNode;
    table.deleteRow(rowIndex);
  };
  var failure = function(e) {
    alert('Failure deleting the client log; please try again');
  };
  var params = 'action=delete_client_log'
  simian.xhr('/admin/clientlog/' + key, params, 'POST', success, failure);
};


/**
 * Toggles a manifest modification between enabled/disabled.
 */
simian.toggleManifestModification = function(key, enabled) {
  var el = simian.$('enable-status-' + key);
  el.innerHTML = 'processing...';
  var success = function(e) {
    var json = JSON.parse(e.responseText);
    if (json['enabled']) {
      el.innerHTML = 'enabled!';
    } else {
      el.innerHTML = 'disabled!';
    }
  };
  var failure = function(e) {
    alert('There was an error toggling a manifest mod; please refresh!');
  };
  var params = 'key=' + key + '&enabled=' + (enabled ? '1' : '0');
  simian.xhr('/admin/manifest_modifications/', params, 'POST', success, failure);
};


/**
 * Toggles a package alias between enabled/disabled.
 */
simian.togglePackageAlias = function(key, enabled) {
  var el = simian.$('enable-status-' + key);
  el.innerHTML = 'processing...';
  var success = function(e) {
    var el = simian.$('enable-status-' + key);
    var json = JSON.parse(e.responseText);
    if (json['enabled']) {
      el.innerHTML = 'enabled!';
    } else {
      el.innerHTML = 'disabled!';
    }
  };
  var failure = function(e) {
    alert('There was an error toggling a package alias; please refresh!');
  };

  var params = 'key_name=' + key + '&enabled=' + (enabled ? '1' : '0');
  simian.xhr('/admin/package_alias/', params, 'POST', success, failure);
};


/**
 * Add an onclick handler to all Apple SUS track checkboxes, for XHR.
 **/
applesus.registerCheckboxes = function() {
  var elements = document.getElementsByClassName('track-checkbox');
  for(var i=0, el; el = elements[i]; i++) {
    el.onclick = function() {
        applesus.toggleProductTrack(this.name, this.value, this.checked);
    };
  }
  var elements = document.getElementsByClassName('manual-override-checkbox');
  for(var i=0, el; el = elements[i]; i++) {
    el.onclick = function() {
        applesus.toggleProductManualOverride(
            this.name, this.checked);
    };
  }
};


/**
 * Use XHR to add or remove a given Apple SUS product from a given track.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {string} track Simian track like unstable, testing, or stable.
 * @param {boolean} enabled Specifies if product id should be in track or not.
 */
applesus.toggleProductTrack = function(productId, track, enabled) {
  var el = simian.$(productId + '-change-status');
  el.innerHTML = 'processing...';

  var success = function(e) {
    var json = JSON.parse(e.responseText);
    var productId = json['product_id'];
    if (json['enabled']) {
      el.innerHTML = json['track'] + ' enabled!';
    } else {
      el.innerHTML = json['track'] + ' removed!';
    }
  };
  var failure = function(e) {
    alert('There was an error toggling a product track; please refresh!');
  };

  var params = 'track=' + track + '&enabled=' + (enabled ? '1' : '0');
  simian.xhr(
      '/admin/applesus/product/' + productId, params, 'POST', success, failure);
};


/**
 * Use XHR to set or unset manual override on a given Apple SUS product.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {boolean} enabled Specifies if product id should be in track or not.
 */
applesus.toggleProductManualOverride = function(productId, enabled) {
  var el = simian.$(productId + '-change-status');
  el.innerHTML = 'processing...';
  var tpd = simian.$(productId + '-testing-promote-date');
  var spd = simian.$(productId + '-stable-promote-date');
  var success = function(e) {
    var json = JSON.parse(e.responseText);
    var productId = json['product_id'];
    if (json['manual_override']) {
      el.innerHTML = 'manual override set!';
      tpd.innerHTML = 'N/A';
      spd.innerHTML = 'N/A';
    } else {
      el.innerHTML = 'manual override unset!';
      tpd.innerHTML = '*reload*';
      spd.innerHTML = '*reload*';
    }
  };
  var failure = function(e) {
    alert(
        'There was an error toggling product manual override; please refresh!');
  };

  var params = 'manual_override=' + (enabled ? '1' : '0');
  simian.xhr(
      '/admin/applesus/product/' + productId, params, 'POST', success, failure);
};



// Extend window.onload to run simian.focusSearch().
window.onload = function() {
  simian.focusSearch();
  simian.initCollapsibles();
  applesus.registerCheckboxes();
};
