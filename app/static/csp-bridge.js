// Replacement for hx-on::after-request="handleAdMgmtModalResponse(event)" (hx-on needs 'unsafe-eval' in CSP).
// Markup: data-adp-after-request="modal"      -> handler for requests of the element or its descendants,
//         data-adp-after-request="modal-self" -> only for requests issued by the element itself.
document.addEventListener("htmx:afterRequest", function (ev) {
  var el = ev.target;
  while (el && el !== document) {
    var mode = el.getAttribute && el.getAttribute("data-adp-after-request");
    if (mode && typeof window.handleAdMgmtModalResponse === "function") {
      if (mode === "modal" || (mode === "modal-self" && ev.detail.elt === el)) {
        window.handleAdMgmtModalResponse(ev);
      }
    }
    el = el.parentNode;
  }
});
