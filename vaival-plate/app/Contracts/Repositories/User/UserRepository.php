<?php

namespace App\Contracts\Repositories\User;

use Auth;
use App\Models\User;
use App\Contracts\Repositories\BaseRepository;
use App\Contracts\Repositories\User\UserRepositoryInterface;

class UserRepository extends BaseRepository implements UserRepositoryInterface
{

    /**
     * Model class for this repository.
     *
     * @return \App\User
     */
    public function model()
    {
        return User::class;
    }
    

    /**
     * Get user by email.
     *
     * @return \App\User
     */
    public function getUserByEmailAndVerficationCode($email, $verification_code)
    {
        return $this->user()->where('email', $email)->where('verification_code', $verification_code)->first();
    }
    
}
