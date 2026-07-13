//Datatables
$(function () {
    // Datatable
    // Skip tables whose only body row is a "no data" placeholder spanning
    // every column via colspan (the standard empty-state idiom used across
    // report tables) — the Responsive extension misreads that colspan as a
    // column-count mismatch and throws "Incorrect column count".
    $('table').each(function () {
      var $table = $(this);
      var colCount = $table.find('thead tr:last').children().length;
      var $rows = $table.find('tbody tr');
      var $firstRowCells = $rows.first().children();
      if (colCount && $rows.length === 1 &&
          $firstRowCells.filter('[colspan]').length === $firstRowCells.length) {
        return;
      }
      $table.DataTable({
      "paging": true,
      "lengthChange": false,
      "searching": true,
      "ordering": true,
      "info": true,
      "autoWidth": true,
      "responsive": true,
      "dom": '<"top"<"left-col"><"center-col"Bl><"right-col"f>>rtip',
      "buttons": [
        {
            extend: 'copy',
            text: '<i class="fa fa-copy"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'csv',
            text:      '<i class="fas fa-file-csv"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'excel',
            text:      '<i class="fa fa-file-excel"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'pdf',
            text:      '<i class="fa fa-file-pdf"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
        {
            extend: 'print',
            text:      '<i class="fa fa-print"></i>',
            title: '',
            className: 'btn-default btn-sm-menu btn-xs',
        },
      ],
      });
    });
  });