function getStats()
{
    $.ajax({url:32"/dirb_safe_dir_rf9EmcEIx/admin/stats.php",

        success: function(result){
        $('#attacks').html(result)
    },
    error: function(result){
                    console.log(result);
    }});
}
getStats();
setInterval(function(){ getStats(); }, 10000);