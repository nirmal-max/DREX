#include "smart/planner.hpp"
#include "smart/report.hpp"
#include "quick/recovery.hpp"
#include "quick/json.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>
static void usage(){std::cout<<"smartscan --source <image|\\\\.\\PhysicalDriveN> [--output plan.json] [--auto-quick]\n";}
int main(int argc,char**argv){std::string source,out;bool auto_quick=false;for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--source"&&i+1<argc)source=argv[++i];else if(a=="--output"&&i+1<argc)out=argv[++i];else if(a=="--auto-quick")auto_quick=true;else if(a=="--help"){usage();return 0;}else{usage();return 2;}}if(source.empty()){usage();return 2;}
 auto r=quick::run_quick_scan(source);auto p=smart::make_plan(r);if(auto_quick&&p.execute_quick){std::cout<<smart::plan_json(p,r);return 0;}if(!out.empty()){std::ofstream f(out);if(!f)return 3;f<<smart::plan_json(p,r);}else std::cout<<smart::plan_json(p,r);
 return r.status==quick::JobStatus::SourceReadError?5:0;}
