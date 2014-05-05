<?php
require_once('PHPSQLParser.php');

$DangerFunction = Array('benchmark','sleep','pg_sleep','concat_ws','system_user','load_file','database','current_user','group_concat','rows_count');
$DangerDB = Array('mysql','information_schema');
$DangerSSV= Array('@@basedir','@@datadir','@@version_compile_os','@@max_allowed_packet','@@max_allowed_packet','@@skip_networking','@@table_type','@@character_set_database','@@log_error','@@tmpdir','@@Uptime');
$score=0;

function checksql($p,$insub=false){
    for($i=0;$i<=count($p);$i++){
        $keyname=key($p);
        if($keyname=='SELECT'){ 
            subchecksql($p[$keyname],$insub); 
        }

        if($keyname=='FROM'){
            subchecksql_from($p[$keyname],$insub);
        }

        if($keyname == 'WHERE'){ 
            subchecksql_where($p[$keyname],$insub); 
        }

        if($keyname == 'ORDER'){
            subchecksql_order($p[$keyname],$insub);
        }

        if($keyname == 'LIMIT'){
            subchecksql_limit($p[$keyname],$insub);
        }

        if(in_array($keyname,array("UNION","UNION ALL"))){
            foreach($p[$keyname] as $sub){
                checksql($sub);
            }
        }
        next($p); 
    } 
}


function splitFromtable($tablestr){
    $exps=explode(".",$tablestr);
    if(count($exps)==1){
        $dbname = "";
        $tablename = $exps[0];
    }else{
        $dbname = str_replace("`","",$exps[0]);
        $tablename = $exps[1];
    }
    return array($dbname,$tablename);
}


function subchecksql_from($p,$insub=false){
    foreach($p as $sub){
        if($sub['expr_type']=='table'){
            is_dangerdbname($sub);
        }
    }
}


function subchecksql_where($p,$insub=false){
    global $score;
    foreach($p as $sub){
        if($sub['expr_type']=='const'){
            is_dangerconst($sub);
        }
        if($sub['expr_type']=='subquery'){
            if(gettype($sub['sub_tree']=='array')){
                checksql($sub['sub_tree']);
            }
        }
        if($sub['expr_type']=='function'){
            //print_r($sub);
            if(gettype($sub['sub_tree'])=='array'){
                subchecksql_where($sub['sub_tree']);
            }
        }
    }
}


function subchecksql($p,$insub=false){
    global $DangerFunction,$score;
    foreach($p as $sub){
        if($sub['expr_type']=='const'){
            is_dangerconst($sub);
        }
        if($sub['expr_type']=='session_variable'){
            is_dangerssv($sub);
        }
        if($sub['expr_type']=='function'){
            if($sub['base_expr']=='concat'){
                specialfunc($sub);
            }
            if(gettype($sub['sub_tree'])=='array'){
                subchecksql($sub['sub_tree']);
            };
            is_dangerFunc($sub);
        }
    }
}


function subchecksql_order($p,$insub=false){
    global $score;
    foreach($p as $sub){
        is_dangerorder($sub);
    }
}


function is_dangerFunc($sub){
    global $DangerFunc,$score;
    if(in_array($sub['base_expr'], $DangerFunction)){
        echo "Deny(function) ==> ",$sub['base_expr'],"\n";
        $score+=2;
    }
}

function is_dangerdbname($sub){ 
    global $DangerDB,$score;
    $dbmst = splitFromtable($sub['table']);
    $dbname = $dbmst[0];
    $tbname = $dbmst[1];
    if(in_array($dbname,$DangerDB)){
        echo "Deny(dbname) ==> ",$sub['table'],"\n";
        $score+=10;
    }
}

function is_dangerssv($sub){
    global $DangerSSV,$score;
    if(in_array($sub['base_expr'],$DangerSSV)){
        echo "Deny(function) ==> ",$sub['base_expr'],"\n";
        $score+=4;
    }
}

function is_dangerconst($sub){
    global $score;
    if(preg_match('/^0x[a-f0-9]+/i',$sub['base_expr'])){
        echo "Deny(const) ==> ",$sub['base_expr'],"\n";
        $score+=2;
    }
}

function is_dangerorder($sub){
    global $score;
    if(!in_array($sub['expr_type'],array('pos','colref'))){
        echo "Deny(order) ==> ",$sub['base_expr'],"\n";
        $score+=2;
    }
}

function is_dangerlimit($p){
    global $score;
    if(!($p['offset']=="" or is_numeric($p['offset']))){
        echo "Deny(limit) ==> ",$sub['offset'],"\n";
        $socre+=4;
    }
    if(!($p['rowcount']=="" or is_numeric($p['rowcount']))){
        echo "Deny(limit) ==> ",$sub['offset'],"\n";
        $socre+=4;
    }
    
}


function subchecksql_limit($p,$insub=false){
    is_dangerlimit($p);
}


function specialfunc($p){
    if($p['base_expr']=='concat'){
        print_r($p);
    }
}


function mysql_query_safe($sql){
    global $score;
    $score=0;
    $parser = new PHPSQLParser();
    $p = $parser->parse($sql); 
    checksql($p);
    if($score<=4){
        echo "Valid SQL";
        //return mysql_query($sql)
    }else{
        echo "Danger! Score: ".$score."\n";
    }
}

mysql_query_safe("select * from mysql.user where id=1 union select 1,2,3,4,5,@@basedir");

?>
