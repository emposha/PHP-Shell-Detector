function init() {
	$("#loader").hide();
  $("dt").live('click', function() {
    var text = $(this).children(".plus");
    if (text.length) {
      $(this).next("dd").slideToggle();
      if (text.text() == "+") {
        text.text("-");
      }
      else {
        text.text("+");
      }
    }
  });
  $(".showline").live('click', function() {
    var id = "li"+$(this).attr("id");
    $( "#"+ id).dialog({height: 440,modal: true, width: 600, title: "Source code"});
    return false;
  });
  $(".source_submit").live('click', function() {
    var id = "for" + $(this).attr("id");
    $("#wrap" + id).dialog({
      autoOpen: false,
      height: 200,
      width: 550,
      modal: true,
      resizable: false,
      title: "File submission",
      buttons: {
        "Submit file to Websecure": function() {
          if ($(".ui-dialog-content form").length) {
            $("#i"+id).removeClass("hidden");
            $("#"+id).submit();
            $(".ui-dialog-content form").remove();
          } else {
            alert("This file already submited");
          }
        },
        "Submit file to Virustotal": function () {
          alert(1);
        }
      }
    });
    $("#wrap" + id).dialog("open");
    return false;
  });
  
  /*$(".source_submit").click(function() {
    var id = "for" + $(this).attr("id");
    $("#"+id).submit();
    $(this).parent().remove();
    $("#i"+id).removeClass("hidden");
    return false;
  })*/
}
$(document).ready(init);
