// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview Functions for expanding/collapsing the menu and saving the
 * state.
 *
 */


goog.provide('simian.menu');

goog.require('goog.dom');
goog.require('goog.dom.classes');
goog.require('goog.net.Cookies');


// Global variable indicating the state of the navigation menu.
simian.menu.menuState =
  goog.net.cookies.get('menupinned', '1') == '1' ? 'pinned' : 'closed';


/**
 * Sets a cookie to save the pinned/closed state of the menu.
 * @param {boolean} val True to set the menu state as pinned in the cookie.
 */
simian.menu.setPinnedCookie = function(val) {
  goog.net.cookies.remove('menupinned');
  goog.net.cookies.set('menupinned', val ? '1' : '0');
};


/**
 * Updates the body's classes to show/hide/style the menu.
 */
simian.menu.updateMenu = function() {
  if (simian.menu.menuState == 'pinned') {
    goog.dom.classes.add(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menuopen');
  } else if (simian.menu.menuState == 'open') {
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.add(goog.dom.getDocument().body, 'menuopen');
  } else {
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menupinned');
    goog.dom.classes.remove(goog.dom.getDocument().body, 'menuopen');
  }
}
goog.exportSymbol('simian.menu.updateMenu', simian.menu.updateMenu);


/**
 * Toggles the menu open/close.
 * @param {boolean} opt_force If true, forces the menu to be toggled.
 */
simian.menu.toggleMenu = function(opt_force) {
  if (simian.menu.menuState == 'closed') {
    simian.menu.menuState = 'open';
  } else {
    if (opt_force) {
      simian.menu.menuState = 'closed';
      simian.menu.setPinnedCookie(false);
    }
  }
  simian.menu.updateMenu();
};
goog.exportSymbol('simian.menu.toggleMenu', simian.menu.toggleMenu);


/**
 * Sets the menu state to pinned and saves cookie.
 */
simian.menu.pinMenu = function() {
  simian.menu.menuState = 'pinned';
  simian.menu.setPinnedCookie(true);
  simian.menu.updateMenu();
};
goog.exportSymbol('simian.menu.pinMenu', simian.menu.pinMenu);


/**
 * Sets the menu state to closed. Useful for hiding the menu on mouseout, etc.
 */
simian.menu.hideMenu = function(e) {
  if (simian.menu.menuState == 'open') {
    simian.menu.menuState = 'closed';
    simian.menu.updateMenu();
  }
};
goog.exportSymbol('simian.menu.hideMenu', simian.menu.hideMenu);

