<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function registerPatient(Request $request)
    {
        try {
            $fields = $request->validate([
                "fullName" => "required|string",
                "email" => "required|string|unique:users,email|email:rfc",
                "password" => "required|string"
            ]);
            
            User::create([
                "name" => $fields["fullName"],
                "email" => $fields["email"],
                "password" => bcrypt($fields["password"])
            ], 201);



            return [
                "message" => "User created."
            ];
        } catch (\Illuminate\Validation\ValidationException $e) {
            return response()->json(["message" => "Validation error", "errors" => $e->errors()], $e->status);
        } catch (\Exception $e) {
            return response()->json(["message" => "An error occurred", "error" => $e->getMessage()], 500);
        }
    }

    public function registerAdmin(Request $request)
    {
        $fields = $request->validate([
            "email" => "required|string|unique:users,email|email:rfc",
            "password" => "required|string"
        ]);

        User::create([
            "name" => "Admin User",
            "email" => $fields["email"],
            "password" => bcrypt($fields["password"])
        ]);

        return [
            "message" => "User created."
        ];
    }

    public function login(Request $request)
{
    try {
        $fields = $request->validate([
            "email" => "required|string|email:rfc",
            "password" => "required|string"
        ]);

        $user = User::where("email", $fields["email"])->first();

        if (!$user || !Hash::check($fields["password"], $user->password)) {
            return response([
                "message" => "Unauthorized",
            ], 401);
        }

        $token = $user->createToken("myapitoken")->plainTextToken;

        return response([
            "message" => "Logged in.",
            "token" => $token
        ], 201);
    } catch (\Exception $e) {
        return response([
            "message" => "An error occurred.",
            "error" => $e->getMessage()
        ], 500);
    }
}


    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return [
            "message" => "Logged out."
        ];
    }

    public function updateUsername(Request $request)
    {
        $fields = $request->validate([
            "fullName" => "required|string",
        ]);

        $user = User::find($request->user()->uid);

        if (!$user) {
            return [
                response([
                    "message" => "User record could not be found.",
                ], 500)
            ];
        }

        $user->name = $fields["fullName"];
        $user->save();

        return [
            "message" => "User name updated.",
            "payload" => [
                "uid" => $user->uid,
                "email" => $user->email,
                "fullName" => $user->name
            ],
        ];
    }

    public function showProfile(Request $request)
    {
        $user = User::find($request->user()->uid);

        if (!$user) {
            return [
                response([
                    "message" => "User record could not be found.",
                ], 500)
            ];
        }

        return [
            "message" => "User profile retrieved.",
            "payload" => [
                "uid" => $user->uid,
                "email" => $user->email,
                "displayName" => $user->name,
                "accountType" => $user->account_type,
                "filledInMedicalChart" => $user->filled_in_medical_chart,
                "isArchived" => $user->is_archived,
            ],
        ];
    }
}
