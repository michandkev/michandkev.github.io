// Countdown Timer
(function () {

    var deadline = '2024/04/20 08:00';

    // fixes "Date.parse(date)" on safari
    function parseDate(date) {
        var parsed = Date.parse(date);
        if (!isNaN(parsed)) return parsed
        return Date.parse(date.replace(/-/g, '/').replace(/[a-z]+/gi, ' '));
    }

    function getTimeRemaining(endtime) {
        let total = parseDate(endtime) - Date.parse(new Date())
        let seconds = Math.floor((total / 1000) % 60)
        let minutes = Math.floor((total / 1000 / 60) % 60)
        let hours = Math.floor((total / (1000 * 60 * 60)) % 24)
        let days = Math.floor(total / (1000 * 60 * 60 * 24))

        return { total, days, hours, minutes, seconds };
    }

    function clock(endtime) {
        let days = document.getElementById('js-timer-days')
        
        var time = getTimeRemaining(endtime);
        var dayCount = time.days + 1;
        var str;
        if (dayCount > 1) {
            days.innerHTML = "" + dayCount + " DAYS TO GO";
        } else if (dayCount == 1) {
            days.innerHTML = "1 DAY TO GO";
        } else if (dayCount == 0) {
            days.innerHTML = "TODAY'S THE DAY";
        } else {
            days.innerHTML = "HOPE YOU HAD FUN";
        }
    }

    clock(deadline);
})();
