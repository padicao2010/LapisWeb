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
})
