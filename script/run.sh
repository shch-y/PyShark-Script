
iter=30



for channel in {"Bad_1","Bad_6","Bad_11","Bad_44","Bad_52","Bad_149","Bad_Total","Good_Total"}
do
output=result2/$channel-iter:$iter-$(date "+%m_%d_%H:%M:%S").txt
echo "Processing $channel"
python -u main.py --input-path ../$channel.cap --iter $iter --cof 0.3 | tee $output
done