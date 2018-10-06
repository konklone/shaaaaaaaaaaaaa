var hasPushstate = Boolean(window.history && history.pushState);

$("form").on("submit", function(event) {
  var domain = $("#domain").val();
  if (domain) {
    var escaped = domain.replace(/^https?:\/\//i, "").replace(/[^\w\.\-:]/g, "");
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
    // don't let mere anchor clicks trigger the event
    // console.log(event);
    if (window.location.pathname == "/")
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
    console.log("Done checking.");

    // transition from loading to main answer body
    $("#results .result").hide();
    $("#results .result.answer").show();
    $("#results .result .word").hide();
    $("#results .result p.details").hide();

    // always fill in algorithm and domain
    $("#results .result .algorithm").html(display[data.cert.algorithm]);
    $("#results .result .domain").html(domain);
    $("a.ssllabs").attr("href", ssllabsUrl(domain));

    var test = domain.toLowerCase();
    if (test == "shaaaaaaaaaaaaa.com")
      $(".extra").html(" and is undoubtedly the most magnificent website in the world").show();
    else
      $(".extra").hide();

    // diagnosis: "good", "bad", "almost"
    $("#results .result ." + data.diagnosis).css("display", "block");

    // TODO: show details
  })
  .fail(function(xhr) {
    hideLoading();
    console.log("Error while checking domain:");
    console.log(xhr.responseJSON.message);

    // load domain
    $("#results .result .domain").html(domain);

    // show results
    $("#results .result").hide();
    $("#results .result.error").show();
    $("#results .result.error .word").show();
  });

  showLoading();
};

var ssllabsUrl = function(domain) {
  return "https://www.ssllabs.com/ssltest/analyze.html?d=" + encodeURIComponent(domain);
};

var showLoading = function() {
  console.log("Checking...");

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
  console.log("Starting over.");

  hideLoading();
  $("#results .result").hide();
  $("#results .result.form").show();
  $("#domain").select().focus();

  return false;
}
$(".start-over").on("click", startOver);

