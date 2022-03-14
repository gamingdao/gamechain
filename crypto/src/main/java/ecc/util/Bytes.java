package ecc.util;

import java.nio.ByteBuffer;
import java.util.Date;


public class Bytes {
 
	
	public static short toShort(byte[] bs) {
		int b0= bs[0]&0xFF;
 	    return (short)(bs.length>1?bs[1]&0xFF|b0<<8:b0);
	}
	
	public static int toInt(byte[] bs) {
		int v=0;
		for(int i=0;i<bs.length&&i<4;i++) {
			v = v<<8|bs[i]&0xFF;
		}
        return v;
	}	 
    public static long toLong(byte[] bs) {
		if(bs.length>8) {/*should not here*/}
      	ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.position(8-bs.length);
        buffer.put(bs, 0, bs.length);
        buffer.flip();
        return buffer.getLong();
    }
    public static String toString(byte[] bs) {
       return new String(bs);
    }

	public static byte[] from(byte is) {
	    return new byte[] {is};
	}
	
	public static byte[] from(short is) {
	    return new byte[] {
	        (byte) ((is >> 8) & 0xFF),   
	        (byte) (is & 0xFF)
	    };
	}	
	public static byte[] from(int is) {
	    return new byte[] {
	        (byte) ((is >> 24) & 0xFF),
	        (byte) ((is >> 16) & 0xFF),   
	        (byte) ((is >> 8) & 0xFF),   
	        (byte) (is & 0xFF)
	    };
	} 
    public static byte[] from(long is) {
    	ByteBuffer buffer = ByteBuffer.allocate(8);
    	buffer.putLong(0, is);
        return buffer.array();
    }
    public static byte[] from(boolean b) {
        return new byte[]{(byte)(b?1:0)};
    }
    public static byte[] from(char c) {
	    return from((short)c);
    }
	public static byte[] from(float f) {
	    return from(Float.floatToIntBits(f));
	} 
    public static byte[] from(double d) {
        return from(Double.doubleToLongBits(d));
    }    

    public static byte[] from(Number num) {
    	if(num==null){return null;}
    	if(num instanceof Integer) {
    		return from((int)num);
    	}else if(num instanceof Long) {
    		return from((long)num);
    	}else if(num instanceof Short) {
    		return from((short)num);
    	}else if(num instanceof Byte) {
    		return from((byte)num);
    	}else if(num instanceof Float) {
    		return from((float)num);
    	}else if(num instanceof Double) {
    		return from((double)num);
    	}
    	return from(num.longValue());
    }
    
    public static byte[] from(String str) {
       	if(str==null){return null;}
    	return str.trim().getBytes();
    }
   
    public static byte[] from(Object obj){
    	if(obj==null){return null;}
    	if(obj instanceof Number) {
    		return from((Number)obj);
    	}else if(obj instanceof Boolean) {
    		return from(((boolean)obj)?1:0);
    	}else if(obj instanceof Character) {
    		return from((char)obj);
    	}else if(obj instanceof Date) {
    		return from(((Date)obj).getTime());
    	}else if(obj instanceof byte[]) {
    		return (byte[])obj;
    	}
    	return from(obj.toString());
    }
   
    public static byte[] xor(byte[] ba1, byte[] ba2){
    	if(ba1==null) {return ba2;}
    	if(ba2==null) {return ba1;}
    	int len = Math.max(ba1.length, ba2.length);
    	byte[] bytes = new byte[len];
    	for(int i=0;i<len;i++) {
       		int b1= i<ba1.length?ba1[i]&0xFF:0;
       		int b2= i<ba2.length?ba2[i]&0xFF:0;
       	    bytes[i]=(byte)(b1^b2);
    	}
        return bytes;
    }
    
	public static void main(String[] args) {
		
		//测试 int 转 byte
		int int0 = 234;
		byte byte0 = (byte)int0;
		System.out.println("byte0=" + byte0);//byte0=-22
		//测试 byte 转 int
		int int1 = byte0;
		System.out.println("int1=" + int1);//int1=-22
		int int2 = byte0&0xFF;
		System.out.println("int2=" + int2);//int2=234
		
		//测试 int 转 byte 数组
		int int3 = 1417;
		byte[] bytesInt = from(int3);
		System.out.println("bytesInt=" + bytesInt);//bytesInt=[B@de6ced
		//测试 byte 数组转 int
		int int4 = toInt(bytesInt);
		System.out.println("int4=" + int4);//int4=1417
		
		//测试 long 转 byte 数组
		long long1 = 2223;
		byte[] bytesLong = from(long1);
		System.out.println("bytes=" + bytesLong);//bytes=[B@c17164
		//测试 byte 数组 转 long
		long long2 = toLong(bytesLong);
		System.out.println("long2=" + long2);//long2=2223
		
		System.out.println("gt=" + Long.toHexString(toLong(from(" 郑郑"))));
		System.out.println("gt2=" + toString(from(" 郑郑")));
		System.out.println("byte129=" +(byte)(129^1));
	}

 
}