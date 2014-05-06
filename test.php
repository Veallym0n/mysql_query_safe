<?php
require_once('src/PHPSQLParser.php');


function sql_get_const($arr){
    $arrs = array();
    foreach($arr as $key){
        array_push($arrs, array($key['expr_type'],$key['base_expr']));
    }
    return $arrs;
}

function array_get_keyname($arr){
    $arrs = array();
    for($i=0;$i<count($arr);$i++){
        array_push($arrs,key($arr));
        next($arr);
    }
    return $arrs;
}




class SQLCHECKER{

    private $DangerFunction = Array('benchmark','sleep','pg_sleep','concat_ws','system_user','load_file','database','current_user','group_concat','rows_count');
    private $DangerDB = Array('mysql','information_schema');
    private $DangerTB = Array('table_schema','column_schema','dual');
    private $DangerSSV= Array('@@basedir','@@datadir','@@version_compile_os','@@max_allowed_packet','@@max_allowed_packet','@@skip_networking','@@table_type','@@character_set_database','@@log_error','@@tmpdir','@@Uptime');
    private $score=0;
    private $nullconst = 0;

    private function is_fullsql($p){
        // is anybody will select datas from nothing?
        $has_from   = 0;
        $keyname    = '';
        for($i=0;$i<count($p);$i++){
            $keyname = key($p);
            if($keyname=='FROM') $has_from = 1;
            next($p);
        }
        if($keyname!="UNION" && $keyname!="UNION ALL"){
            if($has_from==0){
                echo "Deny(sql) ==> not full SQL (with FROM)\n";
                $this->score+=4;
            }
        }
    }

    private function checksql($p,$insub=false){
        $this->is_fullsql($p);
        for($i=0;$i<count($p);$i++){
            $keyname=key($p);
            if($keyname=='SELECT'){ 
                $this->subchecksql($p[$keyname],$insub); 
            }

            if($keyname=='FROM'){
                $this->subchecksql_from($p[$keyname],$insub);
            }

            if($keyname == 'WHERE'){ 
                $this->subchecksql_where($p[$keyname],$insub); 
            }

            if($keyname == 'ORDER'){
                $this->subchecksql_order($p[$keyname],$insub);
            }

            if($keyname == 'LIMIT'){
                $this->subchecksql_limit($p[$keyname],$insub);
            }

            if(in_array($keyname,array("UNION","UNION ALL"))){
                foreach($p[$keyname] as $sub){
                    $this->checksql($sub);
                }
            }
            next($p); 
        } 
    }


    private function _splitFromtable($tablestr){
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


    private function subchecksql_from($p,$insub=false){
        foreach($p as $sub){
            if($sub['expr_type']=='table'){
                $this->is_dangerdbname($sub);
            }
        }
    }


    private function subchecksql_where($p,$insub=false){
        foreach($p as $sub){
            if($sub['expr_type']=='const'){
                $this->is_dangerconst($sub);
            }
            if($sub['expr_type']=='subquery'){
                if(gettype($sub['sub_tree']=='array')){
                    $this->checksql($sub['sub_tree']);
                }
            }
            if($sub['expr_type']=='function'){
                if(gettype($sub['sub_tree'])=='array'){
                    $this->subchecksql_where($sub['sub_tree']);
                }
            }
            if($sub['expr_type']=='colref'){
                $this->is_dangercolref($sub);
            }
        }
    }


    private function subchecksql($p,$insub=false){
        foreach($p as $sub){
            if($sub['expr_type']=='const'){
                $this->is_dangerconst($sub);
            }
            if($sub['expr_type']=='session_variable'){
                $this->is_dangerssv($sub);
            }
            if($sub['expr_type']=='function'){
                if($sub['base_expr']=='concat'){
                    $this->specialfunc($sub);
                }
                if(gettype($sub['sub_tree'])=='array'){
                    $this->subchecksql($sub['sub_tree']);
                };
                $this->is_dangerFunc($sub);
            }
        }
    }


    private function subchecksql_order($p,$insub=false){
        foreach($p as $sub){
            $this->is_dangerorder($sub);
        }
    }

    private function is_dangercolref($sub){
        // this function will detect the comment in SQL
        if(strncmp($sub['base_expr'],"/*",2)==0){
            echo "Deny(colref) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
        if(strncmp($sub['base_expr'],"--",2)==0){
            echo "Deny(colref) ==> ",$sub['base_expr'],"\n";
            $this->socre+=2;
        }
        if(preg_match('/#/',$sub['base_expr'])){
            echo "Deny(colref) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
    }


    private function is_dangerFunc($sub){
        // this function will detect the Dangerous SQL functions
        if(in_array($sub['base_expr'], $this->DangerFunction)){
            echo "Deny(function) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
    }

    private function is_dangerdbname($sub){ 
        // db mysql and db information_schema will be denied, cuz the fool who will use them are idiot
        $dbmst = $this->_splitFromtable($sub['table']);
        $dbname = $dbmst[0];
        $tbname = $dbmst[1];
        if(in_array($dbname,$this->DangerDB)){
            echo "Deny(dbname) ==> ",$sub['table'],"\n";
            $this->score+=8;
        }
        if(in_array($tbname,$this->DangerTB)){
            echo "Deny(tbname) ==> ",$sub['table'],"\n";
            $this->score+=2;
        }
    }

    private function is_dangerssv($sub){
        // this function will detect the Dangerous session values.
        if(in_array($sub['base_expr'],$this->DangerSSV)){
            echo "Deny(session_value) ==> ",$sub['base_expr'],"\n";
            $this->score+=4;
        }
    }

    private function is_dangerconst($sub){
        // this function will detect null const and hex const. nobody will use hex in SQL.
        if(preg_match('/^0x[a-f0-9]+/i',$sub['base_expr'])){
            echo "Deny(const) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
        if($sub['base_expr']=='null'){
            echo "Deny(const) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
    }

    private function is_dangerorder($sub){
        if(!in_array($sub['expr_type'],array('pos','colref'))){
            echo "Deny(order) ==> ",$sub['base_expr'],"\n";
            $this->score+=2;
        }
    }

    private function is_dangerlimit($p){
        if(!($p['offset']=="" or is_numeric($p['offset']))){
            echo "Deny(limit) ==> ",$sub['offset'],"\n";
            $this->score+=4;
        }
        if(!($p['rowcount']=="" or is_numeric($p['rowcount']))){
            echo "Deny(limit) ==> ",$sub['offset'],"\n";
            $this->score+=4;
        }
        
    }

    private function is_dangerexpress($sub){

    }


    private function subchecksql_limit($p,$insub=false){
        $this->is_dangerlimit($p);
    }


    private function specialfunc($p){
        if($p['base_expr']=='concat'){
            print_r($p);
        }
    }


    public function check($sql){
        $parser = new PHPSQLParser();
        $p = $parser->parse($sql); 
        print_r($p);
        $this->checksql($p);
        if($this->score<4){
            return true;
        }else{
            echo "Danger! Score: ".$this->score."\n";
            return false;
        }
    }
}

function mysql_query_safe($sql){
    $_checker = new SQLCHECKER();
    $_isvalid = $_checker->check($sql);
    if($_isvalid){
        echo "\nyeah\n";
    }
}


mysql_query_safe("select * from a  where id=1 and 1=(select 1) union select 1,2,3,benchmark(1000,pg_sleep(100)),5,6 from dual where 1=1 # sqlinject")

?>
