<?php

namespace App\Http\Resources\V1;

use Illuminate\Http\Resources\Json\JsonResource;

class AuthResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        return [
            // "token" => $this->createToken('')->plainTextToken,
            "id" => $this->id,
            "first_name" => $this->first_name,
            "last_name" => $this->last_name,
            "email" => $this->email,
            ];
        // return parent::toArray($request);
    }
}
