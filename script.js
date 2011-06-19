function init() {
  $('dt').click(function() {
    var text = $(this).children('.plus');
    if (text.length) {
      $(this).next('dd').slideToggle();
      if (text.text() == '+') {
        text.text('-');
      }
      else {
        text.text('+');
      }
    }
  });
}
$(document).ready(init);
