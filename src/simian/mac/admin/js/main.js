// Copyright 2011 Google Inc. All Rights Reserved.

/**
 * @fileoverview This is the main JavaScript file for the Simian project.
 *
 */


goog.provide('simian');
goog.provide('applesus');

goog.require('goog.array');
goog.require('goog.dom');
goog.require('goog.events');
goog.require('goog.i18n.DateTimeFormat');
goog.require('goog.i18n.DateTimeParse');
goog.require('goog.json');
goog.require('goog.net.Cookies');
goog.require('goog.net.XhrIo');
goog.require('goog.ui.Component.EventType');
goog.require('goog.ui.Css3MenuButtonRenderer');
goog.require('goog.ui.FilteredMenu');
goog.require('goog.ui.FilterObservingMenuItem');
goog.require('goog.ui.InputDatePicker');
goog.require('goog.ui.KeyboardShortcutHandler');
goog.require('goog.ui.Menu');
goog.require('goog.ui.MenuButton');
goog.require('goog.ui.MenuItem');
goog.require('goog.ui.Select');
goog.require('goog.ui.TriStateMenuItem');
goog.require('goog.ui.AnimatedZippy');

// TODO(user): Build a menu class, and maybe even move the menu source into
// it's own js module.

// Global variable indicating the state of the navigation menu.
simian.menuState =
  goog.net.cookies.get('menupinned', '1') == '1' ? 'pinned' : 'closed';


// Global shortcutHandler for Keyboard Shortcuts.
simian.shortcutHandler = new goog.ui.KeyboardShortcutHandler(document);

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
                      method, params, null, 10000);
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
goog.exportSymbol('simian.deleteClientLogFile', simian.deleteClientLogFile);


/**
 * Toggles a manifest modification between enabled/disabled.
 */
simian.toggleManifestModification = function(key, button) {
  var enable =  'key=' + key + '&enabled=1';
  var disable = 'key=' + key + '&enabled=0';
  simian.ajaxToggle('/admin/manifest_modifications/', enable, disable, button);
};
goog.exportSymbol(
    'simian.toggleManifestModification', simian.toggleManifestModification);


/**
 * Toggles a package alias between enabled/disabled.
 */
simian.togglePackageAlias = function(key, button) {
  var enable =  'key_name=' + key + '&enabled=1';
  var disable = 'key_name=' + key + '&enabled=0';
  simian.ajaxToggle('/admin/package_alias/', enable, disable, button);
};
goog.exportSymbol('simian.togglePackageAlias', simian.togglePackageAlias);


/**
 * Use XHR to add or remove a given Apple SUS product from a given track.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {string} track Simian track like unstable, testing, or stable.
 * @param {Element} button The button that sets the state.
 */
applesus.toggleProductTrack = function(productId, track, button) {
  var enable =  'track=' + track + '&enabled=1';
  var disable = 'track=' + track + '&enabled=0';
  simian.ajaxToggle(
    '/admin/applesus/product/' + productId, enable, disable, button);
};
goog.exportSymbol('applesus.toggleProductTrack', applesus.toggleProductTrack);

/**
 * Use XHR to set or unset manual override on a given Apple SUS product.
 * @param {string} productId Apple SUS Product ID like 042-1234.
 * @param {Element} button The button that sets the state.
 */
applesus.toggleProductManualOverride = function(productId, button) {
  var enable =  'manual_override=1';
  var disable = 'manual_override=0';
  var callback = function(json) {
    goog.dom.$(productId + '-testing-promote-date').innerHTML =
        json['testing_promote_date'] || '';
    goog.dom.$(productId + '-stable-promote-date').innerHTML =
        json['stable_promote_date'] || '';
  };
  simian.ajaxToggle('/admin/applesus/product/' + productId,
                   enable, disable, button, 'manual_override', callback);
};
goog.exportSymbol('applesus.toggleProductManualOverride',
                   applesus.toggleProductManualOverride);


/**
 * Makes AJAX call to /admin/host/uuid with action "upload_logs".
 * @param {string} uuid UUID of the target host.
 * @param {Element} opt_button Button to replace with success msg.
 */
simian.hostUploadLogs = function(uuid, opt_button) {
  simian.xhr('/admin/host/' + uuid,
            'action=upload_logs&uuid=' + uuid,
            'POST',
            function(e) {
              if (opt_button) {
                var email = e.getResponseJson()['email'];
                opt_button.outerHTML = '<span class="success">' +
                    'Logs will be uploaded on next preflight.' +
                    ' (notify: ' + email + ')</span>';
              }
            },
            function(e) {
              alert('oops, please try again');
            });
};
goog.exportSymbol('simian.hostUploadLogs', simian.hostUploadLogs);


/**
 * Replaces all tables with class "barChart" in the document with a colorful
 * bar-chart.
 * @param {Element} opt_el Optional element to render charts within.
 */
simian.renderCharts = function(opt_el) {
  var width = 200;
  goog.array.forEach(
    goog.dom.$$('table', 'barChart', opt_el ? goog.dom.$(opt_el) : null),
    function(table) {
      var values = [];
      var valueStrings = [];
      var dataCells = [];
      goog.array.forEach(goog.dom.$$('tr', null, table), function(tr) {
        var dataCell = goog.dom.getLastElementChild(tr);
        dataCells.push(dataCell);
        goog.dom.classes.add(dataCell, 'datacell');
        goog.dom.setProperties(dataCell, {'width': width});
        goog.dom.classes.add(goog.dom.getFirstElementChild(tr), 'labelcell');
        values.push(parseFloat(goog.dom.getTextContent(dataCell)));
        valueStrings.push(goog.dom.getTextContent(dataCell));
        goog.dom.removeChildren(dataCell);
      });
      var maximum = Math.max.apply(Math, values);
      goog.array.forEach(dataCells, function(dataCell) {
        var val = values.shift();
        var valStr = valueStrings.shift();
        var div = goog.dom.createElement('div');
        goog.dom.classes.add(div, 'databar');
        var barWidth = Math.round(val * (width - 50) / maximum);
        goog.dom.setProperties(div, {'style': 'width: ' + barWidth + 'px'});
        goog.dom.appendChild(dataCell, div);
        var dataDiv = goog.dom.createElement('div');
        goog.dom.classes.add(dataDiv, 'datalabel');
        goog.dom.appendChild(dataDiv, goog.dom.createTextNode(valStr));
        goog.dom.appendChild(dataCell, dataDiv);
      });
      if (table.getAttribute('title')) {
        var th = goog.dom.createDom('tr', null,
          goog.dom.createDom('th', {'colspan':'2'},
            goog.dom.createTextNode(table.getAttribute('title'))
        ));
        goog.dom.insertSiblingBefore(th, goog.dom.getFirstElementChild(table));
      }
    });
};
goog.exportSymbol('simian.renderCharts', simian.renderCharts);


/**
 * Initializes all zippy objects in the page.
 * Toggle must be of class zippy_toggle and title X, and content must have id X.
 * @param {Element} opt_el Optional element to initialize zippys within.
 * @param {boolean} opt_inanimate leave false for AnimatedZippy
 */
simian.zippyfy = function(opt_el, opt_inanimate) {
  goog.array.forEach(
    goog.dom.$$(null, 'zippy_toggle', opt_el ? goog.dom.$(opt_el) : null),
    function(zippy) {
      var content = goog.dom.$(zippy.title);
      if (content) {
        var expanded = goog.dom.classes.has(zippy, 'expanded');
        if (opt_inanimate) {
          var aZippy = new goog.ui.Zippy(zippy, content, expanded);
        } else {
          var aZippy = new goog.ui.AnimatedZippy(zippy, content, expanded);
          aZippy.animationDuration = 130;
        }
      }
    });
};
goog.exportSymbol('simian.zippyfy', simian.zippyfy);


/**
 * Makes an input a date-input.
 * @param {Element} input The input box to choose a date.
 * @param {Function} opt_callback Function called on date change.
 */
simian.makeDateInput = function(input, opt_callback) {
  var PATTERN = "yyyy'-'MM'-'dd";
  var formatter = new goog.i18n.DateTimeFormat(PATTERN);
  var parser = new goog.i18n.DateTimeParse(PATTERN);
  var idp = new goog.ui.InputDatePicker(formatter, parser);
  idp.decorate(input);
  if (opt_callback) {
    goog.events.listen(idp, 'change', opt_callback);
  }
}
goog.exportSymbol('simian.makeDateInput', simian.makeDateInput);


/**
 * Sets a cookie to save the pinned/closed state of the menu.
 * @param {boolean} val True to set the menu state as pinned in the cookie.
 */
simian.setPinnedCookie = function(val) {
  goog.net.cookies.remove('menupinned');
  goog.net.cookies.set('menupinned', val ? '1' : '0');
};


/**
 * Updates the body's classes to show/hide/style the menu.
 */
simian.updateMenu = function() {
  if (simian.menuState == 'pinned') {
    goog.dom.classes.add(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menuopen');
  } else if (simian.menuState == 'open') {
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.add(goog.dom.getDocument().body, 'menuopen');
  } else {
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menuopen');
  }
}
goog.exportSymbol('simian.updateMenu', simian.updateMenu);


/**
 * Toggles the menu open/close.
 * @param {boolean} opt_force If true, forces the menu to be toggled.
 */
simian.toggleMenu = function(opt_force) {
  if (simian.menuState == 'closed') {
    simian.menuState = 'open';
  } else {
    if (opt_force) {
      simian.menuState = 'closed';
      simian.setPinnedCookie(false);
    }
  }
  simian.updateMenu();
};
goog.exportSymbol('simian.toggleMenu', simian.toggleMenu);


/**
 * Sets the menu state to pinned and saves cookie.
 */
simian.pinMenu = function() {
  simian.menuState = 'pinned';
  simian.setPinnedCookie(true);
  simian.updateMenu();
};
goog.exportSymbol('simian.pinMenu', simian.pinMenu);


/**
 * Sets the menu state to closed. Useful for hiding the menu on mouseout, etc.
 */
simian.hideMenu = function(e) {
  if (simian.menuState == 'open') {
    simian.menuState = 'closed';
    simian.updateMenu();
  }
};
goog.exportSymbol('simian.hideMenu', simian.hideMenu);


/**
 * Presents the search box
 */
simian.showSearch = function() {
  goog.dom.classes.add(goog.dom.$('search'), 'open');
  goog.dom.$('search-box').focus();
  simian.registerEscListener(simian.closeSearch);
};
goog.exportSymbol('simian.showSearch', simian.showSearch);


/**
 * Hides the search box
 */
simian.closeSearch = function() {
  goog.dom.classes.remove(goog.dom.$('search'), 'open');
};
goog.exportSymbol('simian.closeSearch', simian.closeSearch);


/**
 * Event listener to hide menu on mouseout. Does not work as expected. DISABLED.
 */
// TODO(user): hide menu on mouseout
simian.registerMenuMouseout = function() {
  goog.events.listen(goog.dom.$('menu'), 'mouseout', simian.hideMenu, true);
};
goog.exportSymbol('simian.registerMenuMouseout', simian.registerMenuMouseout);


/**
 * Event handler for when a new tag in created in the tags filtered menu.
 */
simian.createNewTag = function(e) {
  var item = e.target;
  var itemContent = item.getContentElement();
  var tag = goog.dom.getTextContent(goog.dom.$$('b', null, itemContent)[0]);
  var uuid = goog.dom.$('uuid').innerHTML;
  // If the tag is checked when this event is fired, it'll be unchecked!
  var params = 'action=create&tag=' + tag + '&uuid=' + uuid;
  var success = function(e) {
    var menu = item.getParent();
    var newItem;
    menu.addItem(newItem = new goog.ui.TriStateMenuItem(tag));
    newItem.setCheckedState(goog.ui.TriStateMenuItem.State.FULLY_CHECKED);
  };
  var failure = function(e) {
    alert('Failure creating tag; please refresh and try again.');
  };
  simian.xhr('/admin/tags/', params, 'POST', success, failure);
};


/**
 * Event handler for when an existing tag in the tags filtered menu is toggled.
 */
simian.hostTagClicked = function(e) {
  var item = e.target;
  var tag = item.getCaption();
  var uuid = goog.dom.$('uuid').innerHTML;
  // If the tag is checked when this event is fired, it'll be unchecked!
  var addTag = item.isChecked() ? '0' : '1';
  var params = 'action=change&add=' + addTag + '&tag=' + tag + '&uuid=' + uuid;
  var success = function(e) {};
  var failure = function(e) {
    alert('Failure modifying tag; please refresh and try again.');
  };
  simian.xhr('/admin/tags/', params, 'POST', success, failure);
};


/**
 * Initializes Tags filtered menu for host reports.
 * @param {Object} tags Hash of key tag names and value boolean whether the tag
 *     is applied to the current host or not.
 */
simian.initHostTags = function(tags) {
  var el = goog.dom.$('host-tags');
  var menu = new goog.ui.FilteredMenu();
  menu.setAllowMultiple(true);

  var item;
  for (var tag in tags) {
    menu.addItem(item = new goog.ui.TriStateMenuItem(tag));
    if (tags[tag]) {
      item.setCheckedState(goog.ui.TriStateMenuItem.State.FULLY_CHECKED);
    }
    goog.events.listen(
        item, goog.ui.Component.EventType.CHECK, simian.hostTagClicked);
    goog.events.listen(
        item, goog.ui.Component.EventType.UNCHECK, simian.hostTagClicked);
  }

  var cm = new goog.ui.FilterObservingMenuItem('');
  menu.addItem(cm)

  var button = new goog.ui.MenuButton(
      'Tags', menu, new goog.ui.Css3MenuButtonRenderer());
  button.setFocusablePopupMenu(true);
  button.render(el);

  cm.setObserver(function(item, str) {
    var b = str == '' || tags[str];
    item.setVisible(!b);
    if (!b) {
      item.setContent(this.dom_.createDom(
          'span',
          null,
          '"',
          this.dom_.createDom('b', null, str),
          '" (create tag)'));
    }
  });
  goog.events.listen(
      cm, goog.ui.Component.EventType.ACTION, simian.createNewTag);
};
goog.exportSymbol('simian.initHostTags', simian.initHostTags);


/**
 * Add a one-time event listener to the ESC key
 * @param {Function} callback Called when the event is fired.
 */
// TODO(user): Add a method for triggering ESC events for use in the close
// button, so there is no event listeners hanging around.
simian.registerEscListener = function(callback) {
  goog.events.listenOnce(
      simian.shortcutHandler,
      simian.shortcutHandler.getEventType('esc-key'),
      function(e) { callback(); });
};
goog.exportSymbol('simian.registerEscListener', simian.registerEscListener);


// Extend window.onload to register keyboard shortcuts.
window.onload = function() {
  // When "/" is pressed, focused on the search box.
  simian.shortcutHandler.registerShortcut(
      'focus-search', goog.events.KeyCodes.SLASH);
  goog.events.listen(
      simian.shortcutHandler,
      simian.shortcutHandler.getEventType('focus-search'),
      function(e) { goog.dom.$('search-box').focus() });

  // When Shift+M is pressed, toggle the menu between pinned and closed.
  simian.shortcutHandler.registerShortcut('toggle-menu', goog.events.KeyCodes.M);
  goog.events.listen(
      simian.shortcutHandler,
      simian.shortcutHandler.getEventType('toggle-menu'),
      function(e) {
        if (simian.menuState == 'pinned') {
          simian.toggleMenu(true);
        } else {
          simian.pinMenu();
        }
      });

  // Register the ESC key listener.
  simian.shortcutHandler.registerShortcut('esc-key', goog.events.KeyCodes.ESC);
};


goog.exportSymbol('simian.addClass', goog.dom.classes.add);
goog.exportSymbol('simian.removeClass', goog.dom.classes.remove);
