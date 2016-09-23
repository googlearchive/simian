// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview This is the main JavaScript file for the Simian project.
 *
 */


goog.provide('applesus');
goog.provide('simian');

goog.require('goog.array');
goog.require('goog.dom');
goog.require('goog.dom.TagName');
goog.require('goog.dom.classes');
goog.require('goog.positioning.AnchoredPosition');
goog.require('goog.ui.AnimatedZippy');
goog.require('goog.ui.HoverCard');
goog.require('goog.ui.KeyboardShortcutHandler');
goog.require('goog.ui.TableSorter');
goog.require('goog.ui.Zippy');
goog.require('simian.menu');


/**
 * Global shortcutHandler for Keyboard Shortcuts.
 */
simian.shortcutHandler = new goog.ui.KeyboardShortcutHandler(document);


/**
 * Replaces all tables with class "barChart" in the document with a colorful
 * bar-chart.
 * @param {Element} opt_el Optional element to render charts within.
 */
simian.renderCharts = function(opt_el) {
  var width = 200;
  goog.array.forEach(
    goog.dom.getElementsByTagNameAndClass(
        'table', 'barChart', opt_el ? goog.dom.$(opt_el) : null),
    function(table) {
      var values = [];
      var valueStrings = [];
      var dataCells = [];
      goog.array.forEach(
          goog.dom.getElementsByTagNameAndClass('tr', null, table),
          function(tr) {
            var dataCell = goog.dom.getLastElementChild(tr);
            dataCells.push(dataCell);
            goog.dom.classes.add(dataCell, 'datacell');
            goog.dom.setProperties(dataCell, {'width': width});
            goog.dom.classes.add(
                goog.dom.getFirstElementChild(tr), 'labelcell');
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
        var th = goog.dom.createDom(
            goog.dom.TagName.TR, null,
            goog.dom.createDom(
                goog.dom.TagName.TH, {'colspan': '2'},
                goog.dom.createTextNode(table.getAttribute('title'))));
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
    goog.dom.getElementsByTagNameAndClass(
        null, 'zippy_toggle', opt_el ? goog.dom.$(opt_el) : null),
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
 * Makes UUID links (with class uuidhover) display a HoverCard with host info.
 */
simian.makeUUIDHover = function() {
  var div = goog.dom.createDom(
      goog.dom.TagName.DIV, {
        'id': 'host_popup_container',
        'style': 'display: none; position: absolute; z-index: 840;'
      },
      goog.dom.createDom(
          goog.dom.TagName.DIV, {'id': 'host_popup'},
          goog.dom.createDom(goog.dom.TagName.SPAN, {'class': 'popup_pointer'}),
          goog.dom.createDom(
              goog.dom.TagName.DIV,
              {'id': 'host_popup_loading', 'style': 'display: none;'},
              goog.dom.createDom(goog.dom.TagName.IMG, {
                'src': '/admin/static/loading_222.gif',
                'style': 'width: 16px; height: 16px; margin: 5px 3px;',
                'alt': 'loading'
              })),
          goog.dom.createDom(goog.dom.TagName.DIV, {'id': 'host_popup_info'})));
  goog.dom.appendChild(document.body, div);
  var hc = new goog.ui.HoverCard(
      function(e) { return goog.dom.classes.has(e, 'uuidhover'); }, false);
  var popup = goog.dom.$('host_popup_container');
  var content = goog.dom.$('host_popup_info');
  var loading = goog.dom.$('host_popup_loading');
  hc.setElement(popup);
  var onTrigger = function(event) {
    hc.setPosition(new goog.positioning.AnchoredPosition(
        event.anchor, goog.positioning.Corner.BOTTOM_LEFT));
    return true;
  };
  goog.events.listen(hc, goog.ui.HoverCard.EventType.TRIGGER, onTrigger);
  var onBeforeShow = function() {
    content.innerHTML = loading.innerHTML;
    var host_href = hc.getAnchorElement().getAttribute('href');
    simian.xhr(host_href + '?format=popup', '', 'get',
              function(e) {
                content.innerHTML = e.getResponseText();
                return true;
              },
              function(e) {
                hc.cancelTrigger();
              });
    return true;
  };
  goog.events.listen(hc, goog.ui.HoverCard.EventType.BEFORE_SHOW, onBeforeShow);
};


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


/**
 * Extend window.onload to register keyboard shortcuts
 */
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
        if (simian.menu.menuState == 'pinned') {
          simian.menu.toggleMenu(true);
        } else {
          simian.menu.pinMenu();
        }
      });

  // Register the ESC key listener.
  simian.shortcutHandler.registerShortcut('esc-key', goog.events.KeyCodes.ESC);

  // Make UUID links HoverCards for all pages after load.
  simian.makeUUIDHover();
};


/**
 * Make a table sortable by clicking the header.
 * The table must have THEAD and TBODY tags.
 * @param {string} sortableTableClass Class name of tables to sort.
 * @param {string} alphaSortClass Class name of th/td's that should be
 *     sorted alphabetically instead of numerically.
 */
simian.makeTableSortable = function(sortableTableClass, alphaSortClass) {
  if (!sortableTableClass) {
    sortableTableClass = 'sortable-table';
  }
  if (!alphaSortClass) {
    alphaSortClass = 'sortable-column-sortby-alpha';
  }

  var sortableTables = goog.dom.getElementsByClass(sortableTableClass);
  for (var i = 0, tableToSort; tableToSort = sortableTables[i]; i++) {
    var tableSorter = new goog.ui.TableSorter();
    tableSorter.decorate(tableToSort);
    var headers = simian.getTableHeaders(tableToSort);
    // If a header's class is tagged to sort by alpha, use its index to set sort
    for (var index = 0, node; node = headers[index]; index++) {
      if (node.className) {
        if (node.className.split(' ').indexOf(alphaSortClass) >= 0) {
          tableSorter.setSortFunction(index, goog.ui.TableSorter.alphaSort);
        }
      }
    }
  }
};
goog.exportSymbol('simian.makeTableSortable', simian.makeTableSortable);


/**
 * Get table headers (th) for a table.
 * @param {Element} table Table element to look within for.
 * @return {Array.<Element>} Array of th elements.
 */
simian.getTableHeaders = function(table) {
  var headers = [];
  var node;
  // Get the thead in the table
  var thead;
  node = table.firstElementChild;
  do {
    if (node.tagName == 'THEAD') {
      thead = node;
    } else {
      node = node.nextElementSibling;
    }
  } while (!thead && node);

  if (thead) {
    // Get the tr in thead
    var tr;
    node = thead.firstElementChild;
    do {
      if (node.tagName == 'TR') {
        tr = node;
      } else {
        node = node.nextElementSibling;
      }
    } while (!tr && node);

    if (tr) {
      for (node = tr.firstElementChild; node; node = node.nextElementSibling) {
        headers.push(node);
      }
    }
  }
  return headers;
};


/**
 * Read first file content.
 * Can be called only in user event handler.
 * @param {string} inputId id of input with type="file".
 * @param {Function} callback Callback function called
 *     with file content on success.
 */
simian.getFileContent = function(inputId, callback) {
  var input = goog.dom.$(inputId);
  input.value = '';
  input.onchange = function(evt) {
    if (!evt.target.files.length) {
      return;
    }
    var reader = new FileReader();
    reader.onload = function(e) {
      callback(e.target.result);
    };
    reader.readAsText(evt.target.files[0]);
  };

  // can be triggered only in user event handler
  input.click();
};

/**
 * Replace TextArea content with content of first file.
 * Can be called only in user event handler.
 * @param {string} inputId id of input with type="file".
 * @param {string} areaId TextArea's id.
 */
simian.populateTextAreaFromFile = function(inputId, areaId) {
  simian.getFileContent(inputId, function(content) {
    var textArea = goog.dom.$(areaId);
    textArea.value = content;
    if (textArea.oninput) {
      textArea.oninput(null);
    }
  });
};
goog.exportSymbol(
    'simian.populateTextAreaFromFile', simian.populateTextAreaFromFile);


goog.exportSymbol('simian.addClass', goog.dom.classes.add);
goog.exportSymbol('simian.removeClass', goog.dom.classes.remove);
goog.exportSymbol('simian.setLocationHref', goog.dom.safe.setLocationHref);
goog.exportSymbol('simian.setTextContent', goog.dom.setTextContent);
