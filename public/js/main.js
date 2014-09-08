var hasPushstate = Boolean(window.history && history.pushState);

$("form").on("submit", function(event) {
  var domain = $("#domain").val();
  if (domain) {
    var escaped = domain.replace(/^https?:\/\//i, "").replace(/[^\w\.\-]/g, "");
    checkDomain(escaped);
    if (hasPushstate) {
      history.pushState(escaped, null, "/check/" + escaped);
    }
  }
  event.preventDefault();
});

$(window).on("popstate", function(event) {
  var domain = event.originalEvent.state;
  if (domain) {
    checkDomain(domain);
  } else {
    startOver();
  }
});

var display = {
  "sha256": "SHA-2",
  "sha512": "SHA-2",
  "sha384": "SHA-2",
  "sha224": "SHA-2",
  "sha1": "SHA-1",
  "md5": "MD5",
  "md2": "MD2"
};

var checkDomain = function(domain) {
  console.log("Checking domain: " + domain);

  $.ajax(
    {url: "/api/check/" + domain}
  )
  .done(function(data) {
    hideLoading();

    $("#results .result").hide();
    $("#results .result.answer").show();

    $("#results .result .algorithm").html(display[data.cert.algorithm]);
    $("#results .result .domain").html(domain);

    // topline word: nice, almost, or dang?
    if (data.cert.good) {
      var intergood = true;
      for (var i=0; i<data.intermediates.length; i++) {
        if (!data.intermediates[i].good) {
          intergood = false;
        }
        break;
      }

      if (intergood)
        $("#results .result .word.good").css("display", "block");
      else
        $("#results .result .word.almost").css("display", "block");
    }

    // bad endpoint cert: just focus on that
    else {
      $("#results .result .word.bad").css("display", "block");
    }

  })
  .fail(function(xhr) {
    hideLoading();

    // load domain
    $("#results .result .domain").html(domain);

    // show results
    $("#results .result").hide();
    $("#results .result.error").show();
  });

  showLoading();
};

var showLoading = function() {
  $("#domain").attr("disabled", true);
  $("input[type=submit]")
    .attr("disabled", true)
    .val("Checking...");
  $("#loading").css("display", "inline-block");
};

var hideLoading = function() {
  $("#loading").hide();
  $("#domain").attr("disabled", false);
  $("input[type=submit]")
    .attr("disabled", false)
    .val("Go");

  clearTimeout(loading);
};

var startOver = function() {
  hideLoading();
  $("#results .result").hide();
  $("#results .result.form").show();
  $("#domain").select().focus();

  return false;
}
$(".start-over").on("click", startOver);

