function enableSubmit() {
  let inputs = document.getElementsByClassName("staticrypt-password");
  let btn = document.querySelector('input[type="submit"]');
  let isValid = true;
  for (var i = 0; i < inputs.length; i++) {
    let changedInput = inputs[i];
    if (changedInput.value === null || changedInput.value.trim() === "") {
      isValid = false;
      break;
    }
  }
  btn.disabled = !isValid;
}

$('form#staticrypt-form').submit(function(e){
    $(this).children('input[type=submit]').attr('disabled', 'disabled');
    // this is just for demonstration
    e.preventDefault(); 
    console.log("submitted");
    return false;
});
