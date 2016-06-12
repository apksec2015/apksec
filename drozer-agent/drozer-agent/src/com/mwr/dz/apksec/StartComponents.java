/**
 * 
 */
package com.mwr.dz.apksec;

import java.io.Serializable;
import java.io.ObjectOutputStream.PutField;

import android.R.string;
import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ContentValues;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import java.lang.*;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Liqi, Xiaofang Huang
 *
 */
public class StartComponents {
	
	ContentValues content_values = new ContentValues();
	
	public void startcomponent(String pkgName,String componentName,int flag,Context context){
		
		final int count_putextras = 24; // count of putextra variables
		final int len_array = 2; //default array length
		
		Intent intents[] = new Intent[count_putextras];
		for(int i = 0; i < count_putextras; ++ i){
			intents[i] = new Intent();
			intents[i].setComponent(new ComponentName(pkgName, componentName));
		}
		
		// Prepare data for intent.putExtra. added by hxf 20160114
		// Statement 24 kinds of variables
		// 0
		boolean type_boolean = false;
		intents[0].putExtra("putextra_boolean", type_boolean);
		// 1
		byte type_byte = -128;
		intents[1].putExtra("putextra_byte", type_byte);
		
		// 2
		char type_char = 's';
		intents[2].putExtra("putextra_char", type_char);
		
		// 3
		short type_short = 8191;
		intents[3].putExtra("putextra_short", type_short);
		
		// 4
		int type_int = 2147483647;
		intents[4].putExtra("putextra_int", type_int);
		
		// 5
		long type_long = -9223372036854775808L;
		intents[5].putExtra("putextra_long", type_long);
		
		// 6
		float type_float = 3.14159f;
		intents[6].putExtra("putextra_float", type_float);
		
		// 7
		double type_double = 3.14159;
		intents[7].putExtra("putextra_double", type_double);
		
		// 8
		String type_string = "type_string_java";
		intents[8].putExtra("putextra_string", type_string);
		
		// 9
		CharSequence type_charsequence = "charsequence";
		intents[9].putExtra("putextra_charsequence", type_charsequence);
		
		// 10
		TypeParcelable type_parcelable = new TypeParcelable();
		intents[10].putExtra("putextra_parcelable", type_parcelable);
		
		// 11
		TypeParcelable type_parcelable_array[] = new TypeParcelable[len_array];
		intents[11].putExtra("putextra_parcelable_array", type_parcelable_array);
		
		// 12
		TypeSerializable type_serializable = new TypeSerializable();
		intents[12].putExtra("putextra_serializeble", type_serializable);
		
		// 13
		boolean type_boolean_array[] = new boolean[len_array];
		intents[13].putExtra("putextra_boolean_array", type_boolean_array);
		
		// 14
		byte type_byte_array[] = new byte[len_array];
		intents[14].putExtra("putextra_byte_array", type_byte_array);
		
		// 15
		short type_short_array[] = new short[len_array];
		intents[15].putExtra("putextra_short_array", type_short_array);
		
		// 16
		char type_char_array[] = new char[len_array];
		intents[16].putExtra("putextra_char_array", type_char_array);
		
		// 17
		int type_int_array[] = new int[len_array];
		intents[17].putExtra("putextra_int_array", type_int_array);
		
		// 18
		long type_long_array[] = new long[len_array];
		intents[18].putExtra("putextra_long_array", type_long_array);
		
		// 19
		float type_float_array[] = new float[len_array];
		intents[19].putExtra("putextra_float_array", type_float_array);
		
		// 20
		double type_double_array[] = new double[len_array];
		intents[20].putExtra("putextra_double_array", type_double_array);
		
		// 21
		String type_string_array[] = new String[len_array];
		intents[21].putExtra("putextra_string_array", type_string_array);
		
		// 22
		CharSequence type_charsequence_array[] = new CharSequence[len_array];
		intents[22].putExtra("putextra_charsequence_array", type_charsequence_array);
		
		// 23
		Bundle type_bundle = new Bundle();
		intents[23].putExtra("putextra_bundle", type_bundle);
		
		
		for(int i = 0; i < count_putextras; ++ i){
			
			switch (flag) {
			case 1:
				intents[i].setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
				context.startActivity(intents[i]);
				break;
			case 2:
				context.sendBroadcast(intents[i]);
				break;
			default:
				context.startService(intents[i]);
				break;
			}
		}
		
		System.out.println("over");
	}
	
	
	static class TypeSerializable implements Serializable{
		private static final long serialVersionUID = 1L;
		
		TypeSerializable(){
			super();
		}
		
	}
	
	static class TypeParcelable implements Parcelable{
		
		@Override
		public int describeContents() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public void writeToParcel(Parcel dest, int flags) {
			// TODO Auto-generated method stub
			
		}
		
	}
	

}
