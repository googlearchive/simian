// Copyright 2012 Google Inc. All Rights Reserved.

/**
 * @fileoverview Form validators and other form tools.
 *
 */


goog.require('goog.array');
goog.require('goog.dom');
goog.require('goog.dom.classes');
goog.require('goog.events');
goog.require('goog.i18n.DateTimeFormat');
goog.require('goog.i18n.DateTimeParse');
goog.require('goog.ui.InputDatePicker');

/**
 * Disables/enables all the inputs in a form.
 * @param {Element} form The form to enable/disable.
 * @param {boolean} enabled Enable or disable.
 */
simian.toggleFormEnabled = function(form, enabled) {
  goog.array.forEach(goog.dom.getElementsByTagNameAndClass('input', null, form),
                     function(input) {
                       input.disabled = !enabled;
                     });
  goog.array.forEach(
      goog.dom.getElementsByTagNameAndClass('button', null, form),
      function(button) {
        button.disabled = !enabled;
      });
};


/**
 * Disables the submit button if an invalid input exists in the form.
 * @param {Element} form The form with possibly invalid inputs and submit button
 */
simian.validateSubmit = function(form) {
  form.submit.disabled =
    document.getElementsByClassName('invalid-input').length > 0;
};
goog.exportSymbol('simian.validateSubmit', simian.validateSubmit);


/**
 * Adds the 'invalid-input' class to a field if it fails the regular expression.
 * @param {Element} field The field to validate.
 * @param {RegExp} regexp The regular expression to match.
 * @param {Function} opt_altValid an alternative validation function.
 * @param {Function} opt_callback A callback called after validation.
 */
simian.validateField = function(field, regexp, opt_altValid, opt_callback) {
  if (!regexp.test(field.value) || opt_altValid && !opt_altValid()) {
    goog.dom.classes.add(field, 'invalid-input');
  } else {
    goog.dom.classes.remove(field, 'invalid-input');
  }
  if (opt_callback) {
    opt_callback(false);
  }
  if (field.form) {
    simian.validateSubmit(field.form);
  }
};
goog.exportSymbol('simian.validateField', simian.validateField);


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
    goog.events.listen(idp, goog.ui.DatePicker.Events.CHANGE, opt_callback);
  }
};
goog.exportSymbol('simian.makeDateInput', simian.makeDateInput);
