var myInt;
var scrolling = 0;
var sfactor = 3;
var scount = 10;

function scrollByPix()
{
	if (scount <= 0) {
		sfactor *= 1.2;
		scount = 10;
	}
	parent.lhs.scrollBy(0, sfactor);
	parent.rhs.scrollBy(0, sfactor);
	scount--;
}

function scrollToAnc(num)
{
	// Update the value of the anchor in the form which we use as
	// storage for this value.  setAncValue() will take care of
	// correcting for overflow and underflow of the value and return
	// us the new value.
	num = setAncValue(num);

	// Set location and scroll back a little to expose previous
	// lines.
	//
	// Note that this could be improved: it is possible although
	// complex to compute the x and y position of an anchor, and to
	// scroll to that location directly.
	//
	parent.lhs.location.replace(parent.lhs.location.pathname + "#" + num);
	parent.rhs.location.replace(parent.rhs.location.pathname + "#" + num);

	parent.lhs.scrollBy(0, -30);
	parent.rhs.scrollBy(0, -30);
}

function getAncValue()
{
	return (parseInt(parent.nav.document.diff.real.value));
}

function setAncValue(val)
{
	if (val <= 0) {
		val = 0;
		parent.nav.document.diff.real.value = val;
		parent.nav.document.diff.display.value = "BOF";
		return (val);
	}

	//
	// The way we compute the max anchor value is to stash it
	// inline in the left and right hand side pages-- it's the same
	// on each side, so we pluck from the left.
	//
	maxval = parent.lhs.document.eof.value.value;
	if (val < maxval) {
		parent.nav.document.diff.real.value = val;
		parent.nav.document.diff.display.value = val.toString();
		return (val);
	}

	// this must be: val >= maxval
	val = maxval;
	parent.nav.document.diff.real.value = val;
	parent.nav.document.diff.display.value = "EOF";
	return (val);
}

function stopScroll()
{
	if (scrolling == 1) {
		clearInterval(myInt);
		scrolling = 0;
	}
}

function startScroll()
{
	stopScroll();
	scrolling = 1;
	myInt = setInterval("scrollByPix()", 10);
}

function handlePress(b)
{
	switch (b) {
	case 1:
		scrollToAnc(-1);
		break;
	case 2:
		scrollToAnc(getAncValue() - 1);
		break;
	case 3:
		sfactor = -3;
		startScroll();
		break;
	case 4:
		sfactor = 3;
		startScroll();
		break;
	case 5:
		scrollToAnc(getAncValue() + 1);
		break;
	case 6:
		scrollToAnc(999999);
		break;
	}
}

function handleRelease(b)
{
	stopScroll();
}

function keypress(ev)
{
	var keynum;
	var keychar;

	if (window.event) { // IE
		keynum = ev.keyCode;
	} else if (ev.which) { // non-IE
		keynum = ev.which;
	}

	keychar = String.fromCharCode(keynum);

	if (keychar == "k") {
		handlePress(2);
		return (0);
	} else if (keychar == "j" || keychar == " ") {
		handlePress(5);
		return (0);
	}

	return (1);
}

function ValidateDiffNum()
{
	var val;
	var i;

	val = parent.nav.document.diff.display.value;
	if (val == "EOF") {
		scrollToAnc(999999);
		return;
	}

	if (val == "BOF") {
		scrollToAnc(0);
		return;
	}

	i = parseInt(val);
	if (isNaN(i)) {
		parent.nav.document.diff.display.value = getAncValue();
	} else {
		scrollToAnc(i);
	}

	return (false);
}
