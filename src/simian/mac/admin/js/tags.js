// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview Functions for managing host tags UI.
 *
 */


goog.require('goog.dom');
goog.require('goog.dom.TagName');
goog.require('goog.dom.classes');
goog.require('goog.ui.Component.EventType');
goog.require('goog.ui.Css3MenuButtonRenderer');
goog.require('goog.ui.FilterObservingMenuItem');
goog.require('goog.ui.FilteredMenu');
goog.require('goog.ui.MenuButton');
goog.require('goog.ui.TriStateMenuItem');


/**
 * Event handler for when a new tag in created in the tags filtered menu.
 * @param {goog.events.Event} e Event.
 */
simian.createNewTag = function(e) {
  var item = e.target;
  var itemContent = item.getContentElement();
  var tag = goog.dom.getTextContent(
      goog.dom.getElementsByTagNameAndClass('b', null, itemContent)[0]);
  var uuid = goog.dom.$('uuid').innerHTML;
  var xsrfToken = goog.dom.$('tags-xsrf-token').innerHTML;
  // If the tag is checked when this event is fired, it'll be unchecked!
  var params = 'action=create&tag=' + tag + '&uuid=' + uuid +
      '&xsrf_token=' + xsrfToken;
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
 * @param {goog.events.Event} e Event.
 */
simian.hostTagClicked = function(e) {
  var item = e.target;
  var tag = item.getCaption();
  var uuid = goog.dom.$('uuid').innerHTML;
  var xsrfToken = goog.dom.$('tags-xsrf-token').innerHTML;
  // If the tag is checked when this event is fired, it'll be unchecked!
  var addTag = item.isChecked() ? '0' : '1';
  var params = 'action=change&add=' + addTag + '&tag=' + tag + '&uuid=' + uuid +
      '&xsrf_token=' + xsrfToken;
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
  menu.addItem(cm);

  var button = new goog.ui.MenuButton(
      'Tags', menu, new goog.ui.Css3MenuButtonRenderer());
  button.setFocusablePopupMenu(true);
  button.render(el);

  cm.setObserver(function(item, str) {
    var b = str == '' || tags[str];
    item.setVisible(!b);
    if (!b) {
      item.setContent(this.dom_.createDom(
          goog.dom.TagName.SPAN, null, '"',
          this.dom_.createDom(goog.dom.TagName.B, null, str),
          '" (create tag)'));
    }
  });
  goog.events.listen(
      cm, goog.ui.Component.EventType.ACTION, simian.createNewTag);
};
goog.exportSymbol('simian.initHostTags', simian.initHostTags);
