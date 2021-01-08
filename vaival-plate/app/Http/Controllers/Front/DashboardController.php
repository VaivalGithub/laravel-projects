<?php

namespace App\Http\Controllers\Front;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Contracts\Repositories\User\UserRepositoryInterface;


class DashboardController extends Controller
{
    protected $userRepo;
    /**
     * Create a new Dashboard instance.
     *
     * @return void
     */
    public function __construct(UserRepositoryInterface $userRepo) {

        $this->userRepo = $userRepo;
    }

    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return view('dashboard');
    }

}
