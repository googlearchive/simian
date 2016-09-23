// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview Functions for managing host groups UI.
 *
 */


goog.require('goog.dom');
goog.require('goog.dom.TagName');
goog.require('goog.events');
goog.require('goog.ui.Component.EventType');
goog.require('goog.ui.Css3MenuButtonRenderer');
goog.require('goog.ui.FilterObservingMenuItem');
goog.require('goog.ui.FilteredMenu');
goog.require('goog.ui.MenuButton');
goog.require('goog.ui.TriStateMenuItem');


/**
 * Event handler for when a new group is created in the groups filtered menu.
 * @param {goog.events.Event} e Event.
 */
simian.createNewGroup = function(e) {
  var item = e.target;
  var itemContent = item.getContentElement();
  var group = goog.dom.getTextContent(
      goog.dom.getElementsByTagNameAndClass('b', null, itemContent)[0]);
  var user = goog.dom.$('owner').innerHTML;
  var xsrfToken = goog.dom.$('groups-xsrf-token').innerHTML;
  // If the group is checked when this event is fired, it'll be unchecked!
  var params = 'action=create&group=' + group + '&user=' + user +
      '&xsrf_token=' + xsrfToken;
  var success = function(e) {
    var menu = item.getParent();
    var newItem;
    menu.addItem(newItem = new goog.ui.TriStateMenuItem(group));
    newItem.setCheckedState(goog.ui.TriStateMenuItem.State.FULLY_CHECKED);
  };
  var failure = function(e) {
    alert('Failure creating group; please refresh and try again.');
  };
  simian.xhr('/admin/groups/', params, 'POST', success, failure);
};


/**
 * Event handler for when an existing group in the groups filtered menu is
 * toggled.
 * @param {goog.events.Event} e Event.
 */
simian.hostGroupClicked = function(e) {
  var item = e.target;
  var group = item.getCaption();
  var user = goog.dom.$('owner').innerHTML.trim();
  var xsrfToken = goog.dom.$('groups-xsrf-token').innerHTML;
  // If the group is checked when this event is fired, it'll be unchecked!
  var addGroup = item.isChecked() ? '0' : '1';
  var params = 'action=change&add=' + addGroup + '&group=' + group + '&user=' +
      user + '&xsrf_token=' + xsrfToken;
  var success = function(e) {};
  var failure = function(e) {
    alert('Failure modifying group; please refresh and try again.');
  };
  simian.xhr('/admin/groups/', params, 'POST', success, failure);
};


/**
 * Initializes Groups filtered menu for host reports.
 * @param {Object} groups Hash of key group names and value boolean whether the
 *     group is applied to the current host or not.
 */
simian.initHostGroups = function(groups) {
  var el = goog.dom.$('host-groups');
  var menu = new goog.ui.FilteredMenu();
  menu.setAllowMultiple(true);

  var item;
  for (var group in groups) {
    menu.addItem(item = new goog.ui.TriStateMenuItem(group));
    if (groups[group]) {
      item.setCheckedState(goog.ui.TriStateMenuItem.State.FULLY_CHECKED);
    }
    goog.events.listen(
        item, goog.ui.Component.EventType.CHECK, simian.hostGroupClicked);
    goog.events.listen(
        item, goog.ui.Component.EventType.UNCHECK, simian.hostGroupClicked);
  }

  var cm = new goog.ui.FilterObservingMenuItem('');
  menu.addItem(cm);

  var button = new goog.ui.MenuButton(
      'Groups', menu, new goog.ui.Css3MenuButtonRenderer());
  button.setFocusablePopupMenu(true);
  button.render(el);

  cm.setObserver(function(item, str) {
    var b = str == '' || groups[str];
    item.setVisible(!b);
    if (!b) {
      item.setContent(this.dom_.createDom(
          goog.dom.TagName.SPAN, null, '"',
          this.dom_.createDom(goog.dom.TagName.B, null, str),
          '" (create group)'));
    }
  });
  goog.events.listen(
      cm, goog.ui.Component.EventType.ACTION, simian.createNewGroup);
};
goog.exportSymbol('simian.initHostGroups', simian.initHostGroups);
