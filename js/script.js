/**
 * Main js supporting functionality on the overall website.
 */

/**
 * UI Elements
 */
var mainNavLinks = document.querySelectorAll("header nav ul li a");
var mainNavLinkContainers = document.querySelectorAll("header nav ul li");
var sideMenu = document.getElementById("side-menu-id");

var ourStoryHScroll = document.getElementById("our-story-hscroll");
var ourStoryLeftArrow = document.getElementById("our-story-left-arrow");
var ourStoryRightArrow = document.getElementById("our-story-right-arrow");
var ourStoryCarouselIndicators = document
  .getElementById("our-story-carousel-indcators-list")
  .getElementsByTagName("span");

var modal = document.getElementById("outfit-inspo-modal");
var inspoLink = document.getElementById("outfit-inspo-link");
var closeButton = document.getElementById("close-button");
var modalContent = document.getElementById("outfit-inspo-modal-container");

// Maps carousel index to a tuple of (lower bound scroll, target scroll) for section.
var mOurStoryScrollMapping = new Map();

/**
 * Utility Functions
 */
function getOurStoryMaxScrollX() {
  return ourStoryHScroll.scrollWidth - ourStoryHScroll.clientWidth;
}

function loadOurStoryCarouselIndicators() {
  // Get all elements in the indicators list
  var indicators = ourStoryCarouselIndicators;

  // Loop through all indicators and set display none to reset
  for (var i = 0, l = indicators.length; i < l; i++) {
    indicators[i].style.display = "none";
  }

  // Loop through indicators and figure out how many to show
  let numIndicators = getNumIndicatorsToShow();

  // numIndicators should always be <= indicators.length, but let's just be sure.
  if (numIndicators > indicators.length) {
    numIndicators = indicators.length;
  }

  for (var i = 0; i < numIndicators; i++) {
    indicators[i].style.display = "inline";
    let index = i;
    indicators[i].addEventListener("click", (event) => {
      scrollOurStoryToIndex(index);
    });
  }

  updateOurStoryActiveIndicator();
}

function scrollOurStoryToIndex(index) {
  let scrollToX;
  if (index == 0) {
    scrollToX = 0;
  } else if (index == numIndicators - 1) {
    scrollToX = getOurStoryMaxScrollX();
  } else {
    scrollToX = mOurStoryScrollMapping.get(index)[1];
  }
  ourStoryHScroll.scrollTo({ top: 0, left: scrollToX, behavior: "smooth" });
}

// This creates a mapping of the carousel index to a tuple of the scroll lower bound of each section in the hscroll.
// We determine the max scroll and divide it by the number of indicators. The target scroll is the middle value
// of each section.
function createOurStoryScrollValueMapping() {
  mOurStoryScrollMapping.clear();
  let numIndicators = getNumIndicatorsToShow();
  let maxScrollX = getOurStoryMaxScrollX();

  let singleSectionScrollLength = maxScrollX / numIndicators;

  for (let i = 0; i < numIndicators; i++) {
    let lowerBound = i * singleSectionScrollLength;

    // Add some buffer for the start and end bounds.
    if (numIndicators > 2 && i == 1) {
      lowerBound = lowerBound - 10;
    } else if (numIndicators > 2 && i == numIndicators - 1) {
      lowerBound = lowerBound + 10;
    }

    let mapVal = [lowerBound, lowerBound + singleSectionScrollLength / 2];
    mOurStoryScrollMapping.set(i, mapVal);
  }
}

function getNumIndicatorsToShow() {
  if (window.matchMedia("(max-width: 479px)").matches) {
    numIndicators = 7;
  } else if (window.matchMedia("(max-width: 991px)").matches) {
    numIndicators = 4;
  } else {
    numIndicators = 2;
  }
  return numIndicators;
}

function getOurStoryActiveScrollIndex() {
  let numIndicators = getNumIndicatorsToShow();
  let currentScrollX = ourStoryHScroll.scrollLeft;

  for (let i = 1; i < numIndicators; i++) {
    // Index is active if the current scroll position is between lower bound values in the mapping.
    let currentLowerBound = mOurStoryScrollMapping.get(i - 1)[0];
    let nextLowerBound = mOurStoryScrollMapping.get(i)[0];
    if (
      currentLowerBound <= currentScrollX &&
      currentScrollX < nextLowerBound
    ) {
      return i - 1;
    }
  }
  return numIndicators - 1;
}

function updateOurStoryActiveIndicator() {
  let activeIndex = getOurStoryActiveScrollIndex();

  let indicators = ourStoryCarouselIndicators;
  for (let i = 0; i < indicators.length; i++) {
    let indicator = indicators[i];
    if (i == activeIndex) {
      indicator.classList.add("indicator-active");
    } else {
      indicator.classList.remove("indicator-active");
    }
  }
}

function updateOurStoryNavArrowStates() {
  let activeIndex = getOurStoryActiveScrollIndex();
  let numIndicators = getNumIndicatorsToShow();

  // Add some buffer of 10px to disable the buttons when at the end
  if (activeIndex == 0 && ourStoryHScroll.scrollLeft <= 10) {
    ourStoryLeftArrow.classList.remove("our-story-nav-arrow-active");
    ourStoryRightArrow.classList.add("our-story-nav-arrow-active");
  } else if (
    activeIndex == numIndicators - 1 &&
    ourStoryHScroll.scrollLeft >= getOurStoryMaxScrollX() - 10
  ) {
    ourStoryLeftArrow.classList.add("our-story-nav-arrow-active");
    ourStoryRightArrow.classList.remove("our-story-nav-arrow-active");
  } else {
    ourStoryLeftArrow.classList.add("our-story-nav-arrow-active");
    ourStoryRightArrow.classList.add("our-story-nav-arrow-active");
  }
}

function closeInspoModal() {
  document.body.classList.remove("overflow-y-hidden");

  modalContent.classList.remove("outfit-inspo-modal-content-opened");
  modalContent.classList.add("outfit-inspo-modal-content-closed");

  modal.classList.remove("outfit-inspo-modal-opened");
  modal.classList.add("outfit-inspo-modal-closed");

  setTimeout(function () {
    modal.style.display = "none";
  }, 500);
}

/**
 * Event Listeners
 */
window.addEventListener("scroll", (event) => {
  let header = document.getElementById("header");
  let headerHeight;
  if (window.matchMedia("(max-width: 991px)").matches) {
    headerHeight = document.getElementById(
      "scrolled-header-background"
    ).offsetHeight;
  } else {
    headerHeight = header.offsetHeight;
  }

  let fromTop = window.scrollY;
  let heroBottom =
    document.getElementById("hero-section").offsetHeight - headerHeight - 1;

  // Update nav bar header if screen is scrolled past hero
  if (fromTop > heroBottom) {
    header.classList.add("header-scrolled");
  } else {
    header.classList.remove("header-scrolled");
  }

  // Update nav bar to show active tab
  mainNavLinkContainers.forEach((link) => {
    let linkHash = link.getElementsByTagName("a")[0].hash;
    let section = document.querySelector(linkHash);
    let sectionOffset = section.offsetTop - headerHeight - 1;

    if (
      fromTop > heroBottom &&
      fromTop >= sectionOffset &&
      fromTop < sectionOffset + section.offsetHeight
    ) {
      link.classList.add("nav-active");
    } else {
      link.classList.remove("nav-active");
    }
  });

  // Hide the hero section if past the hero bottom to prevent it from showing behind content
  // (150 px buffer chosen arbitrarily)
  let heroSection = document.getElementById("hero-section");
  heroSection.style.opacity = fromTop > heroBottom + 150 ? 0 : 1;
});

mainNavLinks.forEach((link) => {
  link.addEventListener("click", function (event) {
    if (window.matchMedia("(max-width: 991px)").matches) {
      event.preventDefault();
      sideMenu.checked = false;

      const self = this;
      setTimeout(function () {
        window.location.href = self.href;
      }, 500);
    }
  });
});

window.addEventListener("load", (event) => {
  createOurStoryScrollValueMapping();
  loadOurStoryCarouselIndicators();
  updateOurStoryNavArrowStates();
  modal.style.display = "none";
});

window.addEventListener("resize", (event) => {
  createOurStoryScrollValueMapping();
  loadOurStoryCarouselIndicators();
  updateOurStoryNavArrowStates();
});

ourStoryHScroll.addEventListener("scroll", (event) => {
  updateOurStoryActiveIndicator();
  updateOurStoryNavArrowStates();
});

ourStoryLeftArrow.addEventListener("click", (event) => {
  let activeIndex = getOurStoryActiveScrollIndex();
  if (activeIndex == 0 || activeIndex == 1) {
    scrollOurStoryToIndex(0);
  } else {
    scrollOurStoryToIndex(activeIndex - 1);
  }
});

ourStoryRightArrow.addEventListener("click", (event) => {
  let activeIndex = getOurStoryActiveScrollIndex();
  let numIndicators = getNumIndicatorsToShow();
  if (activeIndex >= numIndicators - 2) {
    scrollOurStoryToIndex(numIndicators - 1);
  } else {
    scrollOurStoryToIndex(activeIndex + 1);
  }
});

window.addEventListener("click", (event) => {
  if (event.target == modal) {
    closeInspoModal();
  }
});

closeButton.addEventListener("click", (event) => {
  closeInspoModal();
});

inspoLink.addEventListener("click", (event) => {
  document.body.classList.add("overflow-y-hidden");

  modal.style.display = "block";
  modalContent.classList.remove("outfit-inspo-modal-content-closed");
  modalContent.classList.add("outfit-inspo-modal-content-opened");

  modal.classList.remove("outfit-inspo-modal-closed");
  modal.classList.add("outfit-inspo-modal-opened");
});

var peteLink = document.getElementById("peter-name");
var petePhoto = document.getElementById("peter-photo");
var peteClicks = 0;
peteLink.addEventListener("click", (event) => {
  peteClicks++;
  var imgUrl = "";
  if (peteClicks % 2 == 0) {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/pete_mobile.jpg')";
    } else {
      imgUrl = "url('/assets/pete_desktop.jpg')";
    }
  } else {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/pete_easteregg_mobile.png')";
    } else {
      imgUrl = "url('/assets/pete_easteregg_desktop.png')";
    }
  }
  petePhoto.style.backgroundImage = imgUrl
});

var neilLink = document.getElementById("neil-name");
var neilPhoto = document.getElementById("neil-photo");
var neilClicks = 0;
neilLink.addEventListener("click", (event) => {
  neilClicks++;
  var imgUrl = "";
  if (neilClicks % 2 == 0) {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/neil_mobile.jpg')";
    } else {
      imgUrl = "url('/assets/neil_desktop.jpg')";
    }
  } else {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/neil_easteregg_mobile.png')";
    } else {
      imgUrl = "url('/assets/neil_easteregg_desktop.png')";
    }
  }
  neilPhoto.style.backgroundImage = imgUrl
});

var ryanLink = document.getElementById("ryan-name");
var ryanPhoto = document.getElementById("ryan-photo");
var ryanClicks = 0;
ryanLink.addEventListener("click", (event) => {
  ryanClicks++;
  var imgUrl = "";
  if (ryanClicks % 2 == 0) {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/ryan_mobile.jpg')";
    } else {
      imgUrl = "url('/assets/ryan_desktop.jpg')";
    }
  } else {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/ryan_easteregg_mobile.png')";
    } else {
      imgUrl = "url('/assets/ryan_easteregg_desktop.png')";
    }
  }
  ryanPhoto.style.backgroundImage = imgUrl
});

var rohanLink = document.getElementById("rohan-name");
var rohanPhoto = document.getElementById("rohan-photo");
var rohanClicks = 0;
rohanLink.addEventListener("click", (event) => {
  rohanClicks++;
  var imgUrl = "";
  if (rohanClicks % 2 == 0) {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/rohan_mobile.jpg')";
    } else {
      imgUrl = "url('/assets/rohan_desktop.jpg')";
    }
  } else {
    if (window.matchMedia("(max-width: 1199px)").matches) {
      imgUrl = "url('/assets/rohan_easteregg_mobile.png')";
    } else {
      imgUrl = "url('/assets/rohan_easteregg_desktop.png')";
    }
  }
  rohanPhoto.style.backgroundImage = imgUrl
});