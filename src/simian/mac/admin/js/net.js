// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview Network related functions (AJaX).
 *
 */


goog.require('goog.array');
goog.require('goog.dom');
goog.require('goog.dom.classes');
goog.require('goog.net.XhrIo');


/**
 * XHR function for AJAX requests.
 * @param {string} url String URL to call.
 * @param {string} params URL encoded string of query/POST parameters.
 * @param {string} method HTTP method to use; GET, POST, PUT, etc.
 * @param {Function} successCallback Callback function called on success.
 * @param {Function} failureCallback Callback function called on failure.
 */
simian.xhr = function(url, params, method, successCallback, failureCallback) {
  goog.net.XhrIo.send(url,
                      function() {
                        if (this.isSuccess()) {
                          successCallback(this);
                        } else {
                          failureCallback(this);
                        }
                      },
                      method, params, null, 10000, true);
};


/**
 * Callback function for simple ajax on/off buttons
 * @param {string} url String URL to call.
 * @param {string} enable String of POST parameters to enable feature.
 * @param {string} disable String of POST parameters to disable feature.
 * @param {Element} button The HTML element thats controls the state.
 * @param {string} opt_responseField The json field that contains the new state.
 * @param {Function} opt_successCallback Callback function called after success.
 */
simian.ajaxToggle = function(url, enable, disable, button, opt_responseField,
                            opt_successCallback) {
  var enabled = goog.dom.classes.has(button, 'istrue');
  var success = function(e) {
    goog.dom.classes.remove(button, 'processing');
    if (e.getResponseJson()[opt_responseField || 'enabled']) {
      goog.dom.classes.add(button, 'istrue');
    } else {
      goog.dom.classes.remove(button, 'istrue');
    }
    if (opt_successCallback) opt_successCallback(e.getResponseJson());
  };
  var failure = function(e) {
    alert('oops, try again.');
  };
  goog.dom.classes.add(button, 'processing');
  simian.xhr(url, enabled ? disable : enable, 'POST', success, failure);
};


/**
 * Submit a form via Ajax
 * @param {Element} form The form with the actions values and submit.
 * @param {Function} opt_successCallback Callback function called after success.
 * @return {boolean} Always return false.
 */
simian.ajaxSubmit = function(form, opt_successCallback) {
  var success = function(e) {
    var json = e.getResponseJson();
    if (json['values']) {
      for (var val in json['values']) {
        if (val['name'] && val['value'] && form[val['name']]) {
          form[val['name']].value = val['value'];
        }
      }
    }
    simian.toggleFormEnabled(form, true);
    goog.dom.classes.add(form, 'saved');
    if (opt_successCallback) {
      opt_successCallback(e.getResponseJson());
    }
  };

  var failure = function(e) {
    simian.toggleFormEnabled(form, true);
    if (e.getResponseJson() && e.getResponseJson()['error']) {
      alert(e.getResponseJson()['error']);
    } else {
      alert('oops, try again.');
    }
  };

  var params = '';
  goog.array.forEach(goog.dom.getElementsByTagNameAndClass('input', null, form),
                     function(input) {
                       if (input.type == 'checkbox') {
                         params += '&' + input.name + '=' + input.checked;
                       } else {
                         params += '&' + input.name + '=' + input.value;
                       }
                     });
  simian.toggleFormEnabled(form, false);
  simian.xhr(form.action, params, form.method, success, failure);
  return false;
};
goog.exportSymbol('simian.ajaxSubmit', simian.ajaxSubmit);


/**
 * Uses XHR to delete a client log file.
 * @param {Element} deleteButton The delete button clicked to call this func.
 * @param {string} xsrfToken
 */
simian.deleteClientLogFile = function(deleteButton, xsrfToken) {
  var key = deleteButton.name;
  var success = function(e) {
    var rowIndex = deleteButton.parentNode.parentNode.rowIndex;
    var table = deleteButton.parentNode.parentNode.parentNode;
    table.deleteRow(rowIndex);
  };
  var failure = function(e) {
    alert('Failure deleting the client log; please try again');
  };
  var params = 'action=delete_client_log&xsrf_token=' + xsrfToken;
  simian.xhr('/admin/host/' + key, params, 'POST', success, failure);
};
goog.exportSymbol('simian.deleteClientLogFile', simian.deleteClientLogFile);


/**
 * Uses XHR to delete a manifest modification.
 * @param {Element} deleteButton The delete button clicked to call this func.
 * @param {string} xsrfToken
 */
simian.deleteManifestModification = function(deleteButton, xsrfToken) {
  var key = deleteButton.name;
  var success = function(e) {
    var rowIndex = deleteButton.parentNode.parentNode.rowIndex;
    var table = deleteButton.parentNode.parentNode.parentNode;
    table.deleteRow(rowIndex);
  };
  var failure = function(e) {
    alert('Failure deleting the manifest mod; please try again');
  };
  var params = 'delete=1&key=' + key + '&xsrf_token=' + xsrfToken;
  simian.xhr('/admin/manifest_modifications', params, 'POST', success, failure);
};
goog.exportSymbol(
    'simian.deleteManifestModification', simian.deleteManifestModification);


/**
 * Toggles a manifest modification between enabled/disabled.
 * @param {string} key Manifestmodifications key.
 * @param {Element} button The HTML element thats controls the state.
 * @param {string} xsrfToken
 */
simian.toggleManifestModification = function(key, button, xsrfToken) {
  var enable = 'key=' + key + '&enabled=1&xsrf_token=' + xsrfToken;
  var disable = 'key=' + key + '&enabled=0&xsrf_token=' + xsrfToken;
  simian.ajaxToggle('/admin/manifest_modifications/', enable, disable, button);
};
goog.exportSymbol(
    'simian.toggleManifestModification', simian.toggleManifestModification);


/**
 * Toggles a package alias between enabled/disabled.
 * @param {string} key Package alias key name.
 * @param {Element} button The HTML element thats controls the state.
 * @param {string} xsrfToken
 */
simian.togglePackageAlias = function(key, button, xsrfToken) {
  var enable = 'key_name=' + key + '&enabled=1&xsrf_token=' + xsrfToken;
  var disable = 'key_name=' + key + '&enabled=0&xsrf_token=' + xsrfToken;
  simian.ajaxToggle('/admin/package_alias/', enable, disable, button);
};
goog.exportSymbol('simian.togglePackageAlias', simian.togglePackageAlias);


/**
 * Use XHR to add or remove a given Apple SUS product from a given track.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {string} track Simian track like unstable, testing, or stable.
 * @param {Element} button The button that sets the state.
 * @param {string} xsrfToken
 */
applesus.toggleProductTrack = function(productId, track, button, xsrfToken) {
  var enable = 'track=' + track + '&enabled=1&xsrf_token=' + xsrfToken;
  var disable = 'track=' + track + '&enabled=0&xsrf_token=' + xsrfToken;
  simian.ajaxToggle(
    '/admin/applesus/product/' + productId, enable, disable, button);
};
goog.exportSymbol('applesus.toggleProductTrack', applesus.toggleProductTrack);


/**
 * Use XHR to set or unset force_install_after_date on an Apple SUS product.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {Element} input The input that contains the desired date.
 * @param {string} xsrfToken
 */
applesus.setForceInstallAfterDate = function(productId, input, xsrfToken) {
  input.disabled = true;
  var success = function(e) {
    input.disabled = false;
  };
  var failure = function(e) {
    alert('Failure setting force_install_after_date; please try again');
  };
  var params = 'force_install_after_date=' + input.value +
      '&xsrf_token=' + xsrfToken;
  simian.xhr(
      '/admin/applesus/product/' + productId, params, 'POST', success, failure);
};
goog.exportSymbol('applesus.setForceInstallAfterDate',
                   applesus.setForceInstallAfterDate);


/**
 * Use XHR to set or unset unattended flag on a given Apple SUS product.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {Element} button The button that sets the state.
 * @param {string} xsrfToken
 */
applesus.toggleProductUnattended = function(productId, button, xsrfToken) {
  var enable = 'unattended=1&xsrf_token=' + xsrfToken;
  var disable = 'unattended=0&xsrf_token=' + xsrfToken;
  simian.ajaxToggle('/admin/applesus/product/' + productId,
      enable, disable, button, 'unattended');
};
goog.exportSymbol('applesus.toggleProductUnattended',
                   applesus.toggleProductUnattended);


/**
 * Use XHR to set or unset manual override on a given Apple SUS product.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {Element} button The button that sets the state.
 * @param {string} xsrfToken
 */
applesus.toggleProductManualOverride = function(productId, button, xsrfToken) {
  var enable = 'manual_override=1&xsrf_token=' + xsrfToken;
  var disable = 'manual_override=0&xsrf_token=' + xsrfToken;
  var callback = function(json) {
    goog.dom.setTextContent(goog.dom.$(productId + '-testing-promote-date'),
        json['testing_promote_date'] || '');
    goog.dom.setTextContent(goog.dom.$(productId + '-stable-promote-date'),
        json['stable_promote_date'] || '');
  };
  simian.ajaxToggle('/admin/applesus/product/' + productId,
                   enable, disable, button, 'manual_override', callback);
};
goog.exportSymbol('applesus.toggleProductManualOverride',
                   applesus.toggleProductManualOverride);


/**
 * Makes AJAX call to /admin/host/uuid with action "upload_logs".
 * @param {string} uuid UUID of the target host.
 * @param {Element}  button Button to replace with success msg.
 * @param {string} xsrfToken
 */
simian.hostUploadLogs = function(uuid, button, xsrfToken) {
  simian.xhr('/admin/host/' + uuid,
            'action=upload_logs&uuid=' + uuid + '&xsrf_token=' + xsrfToken,
            'POST',
            function(e) {
              if (button) {
                var email = e.getResponseJson()['email'];
                button.outerHTML = '<span class="success">' +
                    'Logs will be uploaded on next preflight.' +
                    ' (notify: ' + email + ')</span>';
              }
            },
            function(e) {
              alert('oops, please try again');
            });
};
goog.exportSymbol('simian.hostUploadLogs', simian.hostUploadLogs);
