<?php
require_once('PHPSQLParser.php');

$DangerFunction = Array('benchmark','sleep','pg_sleep','concat_ws','system_user','load_file','database','current_user');
$DangerDB = Array('mysql','information_schema');
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

        if($keyname == 'WHERE'){ subchecksql_where($p[$keyname],$insub); }

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
    global $DangerDB,$score;
    foreach($p as $sub){
        if($sub['expr_type']=='table'){
            $dbmst = splitFromtable($sub['table']);
            $dbname = $dbmst[0];
            $tbname = $dbmst[1];
            if(in_array($dbname,$DangerDB)){
                echo "Deny ==> ",$sub['table'],"\n";
                $score+=10;
            }
        }
    }
}


function subchecksql_where($p,$insub=false){
    global $score;
    foreach($p as $sub){
        if($sub['expr_type']=='const'){
            if(preg_match('/^0x[a-f0-9]+/i',$sub['base_expr'])){
                echo "Deny ==> ",$sub['base_expr'],"\n";
                $score+=2;
            }
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
            if(preg_match('/^0x[a-f0-9]+/i',$sub['base_expr'])){
                echo "Deny ==> ",$sub['base_expr'],"\n";
                $score+=2;
            }
        }
        if($sub['expr_type']=='function'){
            if(gettype($sub['sub_tree'])=='array'){
                subchecksql($sub['sub_tree']);
            };
            if(in_array($sub['base_expr'], $DangerFunction)){
                echo "Deny ==> ",$sub['base_expr'],"\n";
                $score+=2;
            };
        }
    }
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
        //mysql_query($sql)
    }else{
        echo "Danger! Score: ".$score."\n";
    }
}

mysql_query_safe("select owner_name,owner_desc from materials_owner where owner_id='14' and length((select distinct schema_name from `information_schema`.schemata limit 13,1))=62 and 1");

?>
