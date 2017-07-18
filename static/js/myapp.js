$(function() {
  $('#pageChanger').change(function() {
    var checkPage = /page[0-9]+$/
    var href = window.location.href
    if(checkPage.test(href)) {
      window.location.href = href.replace(checkPage, "page" + this.valueAsNumber)
    } else {
      window.location.href = href + "/page" + this.valueAsNumber
    }
  })
  $('a[id^=tr_]').click(function() {
    var par = $(this).parent().parent()
    var src = par.find("pre")
    var dest = par.find("textarea")

    $.ajax({
      url: "/translate/" + this.id.replace(/_[0-9]+$/, ""),
      type: "POST",
      data: {
        src: src.text()
      },
      success: function(results) {
        if(results.status === "SUCCESS") {
          dest.val(results.dest)
        }
      },
      fail: function(results) {}
    })
  })
})
