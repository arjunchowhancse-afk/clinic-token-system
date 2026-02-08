toastr.options = {
  "closeButton": true,
  "progressBar": true,
  "positionClass": "toast-top-right",
  "timeOut": "4000"
};

$(document).ready(function () {

  // Set min date to today
  const today = new Date().toISOString().split('T')[0];
  $('#date').attr('min', today);

  // Booking form
  $('#bookingForm').on('submit', function (e) {
    e.preventDefault();
    
    const btn = $('#submitBtn');
    btn.addClass('loading').prop('disabled', true);

    const data = {
      name: $('#name').val().trim(),
      phone: $('#phone').val().trim(),
      date: $('#date').val()
    };

    $.ajax({
      url: '/api/book',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(data),
      success: function (res) {
        if (res.success) {
          toastr.success(`Token #${res.token} booked for ${res.date}`);
          $('#bookingForm')[0].reset();
        } else {
          toastr.error(res.message);
        }
      },
      error: function () {
        toastr.error("Something went wrong. Please try again.");
      },
      complete: function () {
        btn.removeClass('loading').prop('disabled', false);
      }
    });
  });

  // Check token
  $('#checkTokenForm').on('submit', function (e) {
    e.preventDefault();
    
    const phone = $('#checkPhone').val().trim();
    
    $.ajax({
      url: '/api/check-token',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ phone }),
      success: function (res) {
        if (res.found) {
          $('#patientName').text(res.name);
          $('#bookingDate').text(res.date);
          $('#tokenNumber').text(res.token);
          $('#status').text(res.status.toUpperCase());
          $('#resultCard').removeClass('d-none');
        } else {
          toastr.info("No booking found with this phone number.");
          $('#resultCard').addClass('d-none');
        }
      },
      error: function () {
        toastr.error("Error checking token.");
      }
    });
  });

  // Disable date
  $('#disableDateForm').on('submit', function (e) {
    e.preventDefault();
    const date = $('#disableDate').val();
    
    $.ajax({
      url: '/api/admin/disable-date',
      type: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ date }),
      success: function (res) {
        if (res.success) {
          toastr.warning(res.message);
        }
      }
    });
  });

  // Close today
  $('#closeTodayBtn').click(function () {
    if (!confirm("Are you sure? This will cancel ALL today's tokens!")) return;
    
    $.ajax({
      url: '/api/admin/close-today',
      type: 'POST',
      success: function (res) {
        toastr.error(res.message);
        location.reload();
      }
    });
  });
});