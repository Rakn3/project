let stars = document.getElementById('stars');
let moon = document.getElementById('moon');
//let display = document.querySelector('.display');




window.onscroll = function(){
    let value = scrollY;
    stars.style.top = value + 'px';
    moon.style.top= value * 3 + 'px';

    
}


function sendEmail() {
    Email.send({
        Host : "smtp.mailtrap.io",
        Username : "<Mailtrap username>",
        Password : "<Mailtrap password>",
        To : 'recipient@example.com',
        From : "sender@example.com",
        Subject : "Test email",
        Body : "<html><h2>Header</h2><strong>Bold text</strong><br></br><em>Italic</em></html>"
    }).then(
      message => alert(message)
    );
    }