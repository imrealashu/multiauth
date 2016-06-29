<?php

namespace Imrealashu\MultiAuthGenerator\Console;

use Illuminate\Console\Command;
use Symfony\Component\Finder\Iterator\RecursiveDirectoryIterator;

class MultiAuthClearCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'multiauth:clear {authName}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clears all multi auth';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        $authName = $this->argument('authName');
        
//        $this->deleteViews($authName);
//        $this->deleteControllers($authName);
//        $this->deleteFile(app_path('Http/Controllers/'.ucwords($authName).'Controller.php')); //removing Controller
//        $this->deleteFile(app_path('Http/Middleware/RedirectIfNot'.ucwords($authName).'.php')); //removing Middleware
        $this->deleteFile(app_path(ucwords($authName).'.php')); //removing Model
        
    }
    private function deleteViews($authName){
        $dir = base_path('resources/views/'.$authName);
        $it = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
        $files = new \RecursiveIteratorIterator($it,
            \RecursiveIteratorIterator::CHILD_FIRST);
        foreach($files as $file) {
            if ($file->isDir()){
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }
        rmdir($dir);
    }
    private function deleteControllers($auth_name){
        $dir = app_path('Http/Controllers/'.ucwords($auth_name).'Auth');
        $it = new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS);
        $files = new \RecursiveIteratorIterator($it,
            \RecursiveIteratorIterator::CHILD_FIRST);
        foreach($files as $file) {
            if ($file->isDir()){
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }
        rmdir($dir);
    }
    private function deleteFile($file_name)
    {
        unlink($file_name);
    }
}
