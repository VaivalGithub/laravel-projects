@extends('emails.layouts.main')

@push('styles')
    <style>
        .mini-block-container {
            padding: 10px 50px;
            width: 500px;
        }
        .mini-block {
            width: 498px;
            padding: 0px 100px;
        }
        .code-block {
            background-color: #ffffff;
            padding: 6px 0;
            border: 1px solid #cccccc;
            color: #4d4d4d;
            font-weight: bold;
            font-size: 18px;
            text-align: center;
        }
    </style>
@endpush

@section('content')
    <table cellspacing="0" cellpadding="0" width="600" class="w320">
        <tr>
            <td class="header-md">
                Welcome {{$user->first_name}} {{$user->last_name}} !
            </td>
        </tr>
        <tr>
            <td class="free-text">
                <p>Thank you for registeration with {{config("app.name")}}. Please use activation code below to complete your signup process</p>
            </td>
        </tr>
        <tr>
            <td class="mini-block-container">
                <table cellspacing="0" cellpadding="0" width="100%" style="border-collapse:separate !important;">
                    <tr>
                        <td class="mini-block">
                            <table cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                    <td class="code-block">
                                        {{$user->verification_code}}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td class="free-text">
                <p>If you did not create an account, no further action is required.</p>
            </td>
        </tr>
    </table>
@endsection

